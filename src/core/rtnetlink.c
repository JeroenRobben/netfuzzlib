#include "rtnetlink.h"
#include "interfaces.h"
#include "network_env.h"
#include "callback_wrapper.h"
#include "recv_buffer.h"
#include "libnl.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <net/if_arp.h>
#include <string.h>

static __u32 response_pid(const nfl_sock_full_t *socket) {
    return socket->local_addr ? socket->local_addr->nl.nl_pid : 0;
}

static void free_netlink_msgs(netlink_msg_ll *msgs) {
    while (msgs) {
        netlink_msg_ll *next = msgs->next;
        nlmsg_free(msgs->msg);
        free(msgs);
        msgs = next;
    }
}

static nfl_recv_pkt *netlink_msg_to_network_packet(const netlink_msg_ll *netlink_msg_ll_entry) {
    const size_t length = nlmsg_hdr(netlink_msg_ll_entry->msg)->nlmsg_len;
    nfl_recv_pkt *packet = alloc_recv_pkt(NLMSG_ALIGN(length));
    if (!packet) {
        errno = ENOBUFS;
        return NULL;
    }
    memcpy(packet->buf, nlmsg_hdr(netlink_msg_ll_entry->msg), length);
    return packet;
}

static int send_netlink_done(nfl_sock_full_t *socket, const __u32 pid, const __u32 seq) {
    /* NLMSG_DONE: header followed by an int (always 0, "no error"). */
    const size_t total_len = NLMSG_LENGTH(sizeof(int));
    nfl_recv_pkt *packet = alloc_recv_pkt(NLMSG_ALIGN(total_len));
    if (!packet) {
        return -1;
    }
    struct nlmsghdr *donehdr = packet->buf;
    donehdr->nlmsg_len = total_len;
    /* man netlink(7) says NLM_F_MULTI shouldn't be on NLMSG_DONE, but the Linux kernel sets it
     * (strace ip link), so most parsers tolerate either way. We set it for kernel-compat. */
    donehdr->nlmsg_flags = NLM_F_MULTI;
    donehdr->nlmsg_type = NLMSG_DONE;
    donehdr->nlmsg_pid = pid;
    donehdr->nlmsg_seq = seq;
    *(int *)NLMSG_DATA(donehdr) = 0;
    nfl_log("Adding netlink NLMSG_DONE message");
    sock_append_packet(socket, packet);
    return 0;
}

/* Send a NLMSG_ERROR (positive `error` for ACK-with-success, negative for failure). */
static void send_netlink_error(nfl_sock_full_t *socket, const struct nlmsghdr *request, const int error) {
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (!netlink_msg) {
        return;
    }
    if (!nlmsg_put(netlink_msg, response_pid(socket), request->nlmsg_seq, NLMSG_ERROR, 0, 0)) {
        nlmsg_free(netlink_msg);
        return;
    }
    struct nlmsgerr err_message = { 0 };
    err_message.error = error;
    memcpy(&err_message.msg, request, sizeof(struct nlmsghdr));
    if (nlmsg_append(netlink_msg, &err_message, sizeof(struct nlmsgerr), NLMSG_ALIGNTO)) {
        nlmsg_free(netlink_msg);
        return;
    }

    netlink_msg_ll msg_ll = { .msg = netlink_msg, .next = NULL };
    nfl_recv_pkt *packet = netlink_msg_to_network_packet(&msg_ll);
    if (packet) {
        sock_append_packet(socket, packet);
    }
    nlmsg_free(netlink_msg);
}

static int send_netlink_msgs(nfl_sock_full_t *socket, const netlink_msg_ll *msgs, const bool multipart) {
    for (const netlink_msg_ll *msg_ll = msgs; msg_ll; msg_ll = msg_ll->next) {
        if (multipart) {
            nlmsg_hdr(msg_ll->msg)->nlmsg_flags |= NLM_F_MULTI;
        }
        nfl_recv_pkt *packet = netlink_msg_to_network_packet(msg_ll);
        if (!packet) {
            errno = ENOBUFS;
            return -1;
        }
        sock_append_packet(socket, packet);
    }
    return 0;
}

// Append `response` to the tail of (*head, *tail). Caller has already populated `response`.
static void responses_append(netlink_msg_ll **head, netlink_msg_ll **tail, netlink_msg_ll *response) {
    response->next = NULL;
    if (*head) {
        (*tail)->next = response;
    } else {
        *head = response;
    }
    *tail = response;
}

static int ipv4_subnet_to_prefixlen(const struct sockaddr_in *addr) {
    // netmask is in network byte order, prefix length is popcount of the mask.
    return __builtin_popcount(ntohl(addr->sin_addr.s_addr));
}

static struct nl_msg *address_to_nl_message(const nfl_sock_full_t *socket, const struct nlmsghdr *request, const nfl_l3_iface_t *address) {
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (!netlink_msg) {
        errno = ENOBUFS;
        return NULL;
    }

    struct ifa_cacheinfo cacheinfo = {
        .ifa_prefered = 3000,
        .ifa_valid = 3000,
        .cstamp = 10000,
        .tstamp = 20000,
    };

    int err = !nlmsg_put(netlink_msg, response_pid(socket), request->nlmsg_seq, RTM_NEWADDR, 0, 0);
    struct ifaddrmsg ifaddr = { 0 };
    ifaddr.ifa_index = address->parent_l2_iface->index;
    ifaddr.ifa_family = address->addr->s.sa_family;
    ifaddr.ifa_flags = IFA_F_PERMANENT;

    if (address->addr->s.sa_family == AF_INET) {
        const struct sockaddr_in *ipv4_address = (struct sockaddr_in *)address->addr;
        ifaddr.ifa_prefixlen = ipv4_subnet_to_prefixlen((struct sockaddr_in *)address->netmask);

        if (ipv4_address->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            ifaddr.ifa_scope = RT_SCOPE_HOST;
        } else if ((ntohl(ipv4_address->sin_addr.s_addr) & 0xFFFF0000) == 0xA9FE0000) {
            // RFC 3927: 169.254.0.0/16 link-local.
            ifaddr.ifa_scope = RT_SCOPE_LINK;
        } else {
            ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
        }
        err |= nlmsg_append(netlink_msg, &ifaddr, sizeof(struct ifaddrmsg), NLMSG_ALIGNTO);

        const int ifa_flags_attr = IFA_F_PERMANENT;
        err |= nla_put(netlink_msg, IFA_LOCAL, sizeof(in_addr_t), &ipv4_address->sin_addr.s_addr);
        err |= nla_put(netlink_msg, IFA_ADDRESS, sizeof(in_addr_t), &ipv4_address->sin_addr.s_addr);
        if (ifaddr.ifa_prefixlen < 32) {
            struct sockaddr_in broadcast_addr;
            get_l3_iface_broadcast_addr(address, &broadcast_addr);
            err |= nla_put(netlink_msg, IFA_BROADCAST, sizeof(in_addr_t), &broadcast_addr.sin_addr.s_addr);
        }
        const size_t name_len = strlen(address->parent_l2_iface->name) + 1; // include NUL
        err |= nla_put(netlink_msg, IFA_LABEL, (int)name_len, address->parent_l2_iface->name);
        err |= nla_put(netlink_msg, IFA_FLAGS, sizeof(ifa_flags_attr), &ifa_flags_attr);
        err |= nla_put(netlink_msg, IFA_CACHEINFO, sizeof(struct ifa_cacheinfo), &cacheinfo);
    } else if (address->addr->s.sa_family == AF_INET6) {
        const struct sockaddr_in6 *ipv6_address = (struct sockaddr_in6 *)address->addr;
        ifaddr.ifa_prefixlen = address->prefix;

        if (IN6_IS_ADDR_LOOPBACK(&ipv6_address->sin6_addr)) {
            ifaddr.ifa_scope = RT_SCOPE_HOST;
        } else if (IN6_IS_ADDR_LINKLOCAL(&ipv6_address->sin6_addr)) {
            ifaddr.ifa_scope = RT_SCOPE_LINK;
        } else {
            ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
        }

        err |= nlmsg_append(netlink_msg, &ifaddr, sizeof(struct ifaddrmsg), NLMSG_ALIGNTO);
        const int ifa_flags_attr = IFA_F_PERMANENT;
        err |= nla_put(netlink_msg, IFA_ADDRESS, sizeof(struct in6_addr), &ipv6_address->sin6_addr);
        err |= nla_put(netlink_msg, IFA_FLAGS, sizeof(ifa_flags_attr), &ifa_flags_attr);
        err |= nla_put(netlink_msg, IFA_CACHEINFO, sizeof(struct ifa_cacheinfo), &cacheinfo);
    } else {
        errno = EINVAL;
        nlmsg_free(netlink_msg);
        return NULL;
    }
    if (err) {
        errno = ENOBUFS;
        nlmsg_free(netlink_msg);
        return NULL;
    }

    return netlink_msg;
}

static struct nl_msg *device_to_nl_message(const nfl_sock_full_t *socket, const struct nlmsghdr *request, const nfl_l2_iface_t *device) {
    struct nl_msg *netlink_message = nlmsg_alloc();
    if (!netlink_message) {
        return NULL;
    }
    int err = !nlmsg_put(netlink_message, response_pid(socket), request->nlmsg_seq, RTM_NEWLINK, 0, 0);
    if (err) {
        nlmsg_free(netlink_message);
        return NULL;
    }
    struct ifinfomsg ifinfo = { 0 };
    ifinfo.ifi_family = AF_UNSPEC;
    ifinfo.ifi_type = l2_iface_is_loopback(device) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
    ifinfo.ifi_index = (int)device->index;
    ifinfo.ifi_flags = device->flags;
    ifinfo.ifi_change = 0xFFFFFFFF;
    err = nlmsg_append(netlink_message, &ifinfo, sizeof(struct ifinfomsg), NLMSG_ALIGNTO);

    err |= nla_put(netlink_message, IFLA_ADDRESS, sizeof(device->hw_addr), device->hw_addr);
    err |= nla_put(netlink_message, IFLA_BROADCAST, sizeof(device->hw_broadcast_addr), device->hw_broadcast_addr);
    /* IFLA_IFNAME must include the NUL terminator. */
    const size_t name_len = strlen(device->name) + 1;
    err |= nla_put(netlink_message, IFLA_IFNAME, (int)name_len, device->name);
    err |= nla_put(netlink_message, IFLA_MTU, sizeof(device->mtu), &device->mtu);

    const char *qdisc = l2_iface_is_loopback(device) ? "noqueue" : "fq_codel";
    err |= nla_put(netlink_message, IFLA_QDISC, (int)(strlen(qdisc) + 1), qdisc);

    // Modern attributes the kernel emits
    const uint8_t operstate = (device->flags & IFF_RUNNING) ? 6 /* IF_OPER_UP */ : 2 /* IF_OPER_DOWN */;
    const uint8_t linkmode = 0;
    const uint8_t carrier = (device->flags & IFF_RUNNING) ? 1 : 0;
    const uint32_t group = 0;
    const uint32_t txqlen = 1000;
    const uint32_t num_q = 1;
    const uint32_t gso_max_segs = 65535;
    const uint32_t gso_max_size = 65536;
    const uint32_t promiscuity = 0;
    err |= nla_put(netlink_message, IFLA_OPERSTATE, sizeof(operstate), &operstate);
    err |= nla_put(netlink_message, IFLA_LINKMODE, sizeof(linkmode), &linkmode);
    err |= nla_put(netlink_message, IFLA_CARRIER, sizeof(carrier), &carrier);
    err |= nla_put(netlink_message, IFLA_GROUP, sizeof(group), &group);
    err |= nla_put(netlink_message, IFLA_TXQLEN, sizeof(txqlen), &txqlen);
    err |= nla_put(netlink_message, IFLA_NUM_TX_QUEUES, sizeof(num_q), &num_q);
    err |= nla_put(netlink_message, IFLA_NUM_RX_QUEUES, sizeof(num_q), &num_q);
    err |= nla_put(netlink_message, IFLA_GSO_MAX_SEGS, sizeof(gso_max_segs), &gso_max_segs);
    err |= nla_put(netlink_message, IFLA_GSO_MAX_SIZE, sizeof(gso_max_size), &gso_max_size);
    err |= nla_put(netlink_message, IFLA_PROMISCUITY, sizeof(promiscuity), &promiscuity);

    struct rtnl_link_stats stats = { 0 };
    err |= nla_put(netlink_message, IFLA_STATS, sizeof(struct rtnl_link_stats), &stats);
    if (err) {
        nlmsg_free(netlink_message);
        return NULL;
    }
    return netlink_message;
}

// Walk attributes for an ifinfomsg-shaped request.
static struct rtattr *find_ifla_attribute(struct nlmsghdr *hdr, const unsigned short rta_type) {
    if (hdr->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
        return NULL;
    }
    int len = (int)(hdr->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg)));
    struct ifinfomsg *ifinfo = NLMSG_DATA(hdr);
    for (struct rtattr *rta = IFLA_RTA(ifinfo); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == rta_type) {
            return rta;
        }
    }
    return NULL;
}

static bool is_dump_request(const struct nlmsghdr *hdr) {
    return (hdr->nlmsg_flags & (NLM_F_ROOT | NLM_F_DUMP)) != 0;
}

static void handle_getaddr(nfl_sock_full_t *socket, struct nlmsghdr *request) {
    int filter_domain = 0;
    if (request->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtgenmsg))) {
        filter_domain = ((struct rtgenmsg *)NLMSG_DATA(request))->rtgen_family;
    }
    nfl_log("Handling Netlink GETADDR request, filter_domain: %d", filter_domain);

    netlink_msg_ll *responses = NULL;
    netlink_msg_ll *tail = NULL;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *device = get_l2_iface_by_index(i);
        if (!device) {
            continue;
        }
        for (const nfl_l3_iface_t *address = device->l3_interfaces; address; address = address->next) {
            if (filter_domain && filter_domain != address->addr->s.sa_family) {
                continue;
            }
            struct nl_msg *msg = address_to_nl_message(socket, request, address);
            if (!msg) {
                continue;
            }
            netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
            if (!response) {
                nlmsg_free(msg);
                errno = ENOBUFS;
                continue;
            }

            char addr_str[NETWORK_DEVICE_STR_MAX_LEN];
            nfl_log("GETADDR matched: %s", network_device_address_to_string(address, addr_str, sizeof(addr_str)));
            response->msg = msg;
            responses_append(&responses, &tail, response);
        }
    }
    if (responses) {
        nfl_log("GETADDR sending response(s)");
        send_netlink_msgs(socket, responses, true);
        free_netlink_msgs(responses);
    } else {
        nfl_log("GETADDR empty result, sending NLMSG_DONE only");
    }
    // Always terminate dumps so callers don't block on recvmsg.
    send_netlink_done(socket, response_pid(socket), request->nlmsg_seq);
}

static void handle_getlink(nfl_sock_full_t *socket, struct nlmsghdr *request) {
    if (request->nlmsg_len < NLMSG_LENGTH(sizeof(struct ifinfomsg))) {
        send_netlink_error(socket, request, -EINVAL);
        return;
    }
    const struct ifinfomsg *ifinfo = NLMSG_DATA(request);
    const bool dump = is_dump_request(request);
    struct rtattr *rta_name_filter = ifinfo->ifi_index == 0 ? find_ifla_attribute(request, IFLA_IFNAME) : NULL;

    nfl_log("Handling Netlink GETLINK request, ifi_index=%d, dump=%d, name_filter_set=%d",
                  ifinfo->ifi_index, dump, rta_name_filter != NULL);

    netlink_msg_ll *responses = NULL;
    netlink_msg_ll *tail = NULL;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *device = get_l2_iface_by_index(i);
        if (!device) {
            continue;
        }
        if (ifinfo->ifi_index > 0 && device->index != (unsigned int)ifinfo->ifi_index) {
            continue;
        }
        if (rta_name_filter) {
            const char *want = RTA_DATA(rta_name_filter);
            if (strncmp(want, device->name, RTA_PAYLOAD(rta_name_filter)) != 0) {
                continue;
            }
        }
        struct nl_msg *msg = device_to_nl_message(socket, request, device);
        if (!msg) {
            continue;
        }
        netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
        if (!response) {
            nlmsg_free(msg);
            errno = ENOBUFS;
            continue;
        }
        response->msg = msg;
        responses_append(&responses, &tail, response);
        if (!dump) {
            break; // single-target query: stop at first match
        }
    }

    if (!responses) {
        if (dump) {
            send_netlink_done(socket, response_pid(socket), request->nlmsg_seq);
        } else {
            send_netlink_error(socket, request, -ENODEV);
        }
        return;
    }
    send_netlink_msgs(socket, responses, dump);
    free_netlink_msgs(responses);
    if (dump) {
        send_netlink_done(socket, response_pid(socket), request->nlmsg_seq);
    }
}

static void handle_getneigh(nfl_sock_full_t *socket, struct nlmsghdr *request) {
    /* Neighbor table is empty in the model for now. Always emit an empty NLMSG_DONE so callers
     * don't block in recvmsg waiting for a terminator. */
    nfl_log("Handling Netlink GETNEIGH request: empty result");
    send_netlink_done(socket, response_pid(socket), request->nlmsg_seq);
}

// Build an RTM_NEWROUTE response for a given destination/gateway/interface combo.
static struct nl_msg *route_to_nl_message(const nfl_sock_full_t *socket,
                                          const struct nlmsghdr *request,
                                          const unsigned char family,
                                          const unsigned char dst_len,
                                          const unsigned char scope,
                                          const unsigned char rt_type,
                                          const void *dst, const size_t dst_size,
                                          const void *gw, const size_t gw_size,
                                          const void *prefsrc, const size_t prefsrc_size,
                                          const unsigned int oif) {
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (!netlink_msg) {
        return NULL;
    }
    int err = !nlmsg_put(netlink_msg, response_pid(socket), request->nlmsg_seq, RTM_NEWROUTE, 0, 0);
    struct rtmsg rt = { 0 };
    rt.rtm_family = family;
    rt.rtm_dst_len = dst_len;
    rt.rtm_table = RT_TABLE_MAIN;
    rt.rtm_protocol = RTPROT_KERNEL;
    rt.rtm_scope = scope;
    rt.rtm_type = rt_type;
    err |= nlmsg_append(netlink_msg, &rt, sizeof(struct rtmsg), NLMSG_ALIGNTO);

    if (dst && dst_len > 0) {
        err |= nla_put(netlink_msg, RTA_DST, (int)dst_size, dst);
    }
    if (gw) {
        err |= nla_put(netlink_msg, RTA_GATEWAY, (int)gw_size, gw);
    }
    if (prefsrc) {
        err |= nla_put(netlink_msg, RTA_PREFSRC, (int)prefsrc_size, prefsrc);
    }
    if (oif) {
        err |= nla_put(netlink_msg, RTA_OIF, sizeof(uint32_t), &oif);
    }
    if (err) {
        nlmsg_free(netlink_msg);
        return NULL;
    }
    return netlink_msg;
}

static void handle_getroute(nfl_sock_full_t *socket, struct nlmsghdr *request) {
    int filter_family = 0;
    if (request->nlmsg_len >= NLMSG_LENGTH(sizeof(struct rtmsg))) {
        filter_family = ((struct rtmsg *)NLMSG_DATA(request))->rtm_family;
    }

    netlink_msg_ll *responses = NULL;
    netlink_msg_ll *tail = NULL;

    // Per-interface connected routes (dst = subnet, scope = LINK).
    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *device = get_l2_iface_by_index(i);
        if (!device) {
            continue;
        }
        for (const nfl_l3_iface_t *l3 = device->l3_interfaces; l3; l3 = l3->next) {
            const unsigned char family = l3->addr->s.sa_family;
            if (filter_family && filter_family != family) {
                continue;
            }
            struct nl_msg *msg = NULL;
            if (family == AF_INET) {
                const struct sockaddr_in *addr = &l3->addr->s4;
                const struct sockaddr_in *mask = &l3->netmask->s4;
                const uint32_t subnet = addr->sin_addr.s_addr & mask->sin_addr.s_addr;
                const uint8_t prefix = (uint8_t)__builtin_popcount(ntohl(mask->sin_addr.s_addr));
                msg = route_to_nl_message(socket, request, AF_INET, prefix, RT_SCOPE_LINK, RTN_UNICAST,
                                          &subnet, sizeof(uint32_t),
                                          NULL, 0,
                                          &addr->sin_addr.s_addr, sizeof(uint32_t),
                                          device->index);
            } else if (family == AF_INET6) {
                const struct sockaddr_in6 *addr = &l3->addr->s6;
                msg = route_to_nl_message(socket, request, AF_INET6, (uint8_t)l3->prefix, RT_SCOPE_LINK, RTN_UNICAST,
                                          &addr->sin6_addr, sizeof(struct in6_addr),
                                          NULL, 0,
                                          &addr->sin6_addr, sizeof(struct in6_addr),
                                          device->index);
            }
            if (!msg) {
                continue;
            }
            netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
            if (!response) {
                nlmsg_free(msg);
                continue;
            }
            response->msg = msg;
            responses_append(&responses, &tail, response);
        }
    }

    // Default routes via configured gateways (dst_len = 0).
    network_env *env = get_network_env();
    if (env->ipv4_gateway && (!filter_family || filter_family == AF_INET)) {
        const nfl_l3_iface_t *iface = env->ipv4_gateway->interface;
        const uint32_t zero = 0;
        struct nl_msg *msg = route_to_nl_message(socket, request, AF_INET, 0, RT_SCOPE_UNIVERSE, RTN_UNICAST,
                                                 &zero, sizeof(uint32_t),
                                                 &env->ipv4_gateway->gateway_addr, sizeof(uint32_t),
                                                 &iface->addr->s4.sin_addr.s_addr, sizeof(uint32_t),
                                                 iface->parent_l2_iface->index);
        if (msg) {
            netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
            if (response) {
                response->msg = msg;
                responses_append(&responses, &tail, response);
            } else {
                nlmsg_free(msg);
            }
        }
    }
    if (env->ipv6_gateway && (!filter_family || filter_family == AF_INET6)) {
        const nfl_l3_iface_t *iface = env->ipv6_gateway->interface;
        const struct in6_addr zero = { 0 };
        struct nl_msg *msg = route_to_nl_message(socket, request, AF_INET6, 0, RT_SCOPE_UNIVERSE, RTN_UNICAST,
                                                 &zero, sizeof(struct in6_addr),
                                                 &env->ipv6_gateway->gateway_addr, sizeof(struct in6_addr),
                                                 &iface->addr->s6.sin6_addr, sizeof(struct in6_addr),
                                                 iface->parent_l2_iface->index);
        if (msg) {
            netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
            if (response) {
                response->msg = msg;
                responses_append(&responses, &tail, response);
            } else {
                nlmsg_free(msg);
            }
        }
    }

    if (responses) {
        send_netlink_msgs(socket, responses, true);
        free_netlink_msgs(responses);
    }
    send_netlink_done(socket, response_pid(socket), request->nlmsg_seq);
}

ssize_t sendmsg_netlink(nfl_sock_full_t *socket, const struct msghdr *msg) {
    if (msg->msg_iovlen == 0) {
        return 0;
    }

    ssize_t bytes_processed = 0;
    for (size_t iov_array_offset = 0; iov_array_offset < msg->msg_iovlen; iov_array_offset++) {
        const struct iovec *iov = &msg->msg_iov[iov_array_offset];
        ssize_t length = (ssize_t)iov->iov_len;
        bytes_processed += length;

        for (struct nlmsghdr *hdr = iov->iov_base; NLMSG_OK(hdr, length); hdr = NLMSG_NEXT(hdr, length)) {
            // Kernel: every request must carry NLM_F_REQUEST. NLMSG_NOOP/DONE are exempt.
            if (!(hdr->nlmsg_flags & NLM_F_REQUEST) &&
                hdr->nlmsg_type != NLMSG_NOOP && hdr->nlmsg_type != NLMSG_DONE) {
                send_netlink_error(socket, hdr, -EINVAL);
                continue;
            }

            switch (hdr->nlmsg_type) {
            case NLMSG_NOOP:
                if (hdr->nlmsg_flags & NLM_F_ACK) {
                    send_netlink_error(socket, hdr, 0);
                }
                continue;
            case NLMSG_DONE:
                continue;
            case RTM_GETADDR:
                handle_getaddr(socket, hdr);
                continue;
            case RTM_GETLINK:
                handle_getlink(socket, hdr);
                continue;
            case RTM_GETNEIGH:
                handle_getneigh(socket, hdr);
                continue;
            case RTM_GETROUTE:
                handle_getroute(socket, hdr);
                continue;
            default:
                /* Unsupported message type: kernel returns NLMSG_ERROR with -EOPNOTSUPP
                 * (regardless of NLM_F_ACK. Apps need to know the op didn't take). */
                nfl_log("Got unsupported netlink message, type: %d", hdr->nlmsg_type);
                send_netlink_error(socket, hdr, -EOPNOTSUPP);
                continue;
            }
        }
    }
    return bytes_processed;
}

ssize_t recvmsg_netlink(nfl_sock_full_t *socket, struct msghdr *msg, const nfl_recv_flags flags) {
    /* Drop a fully-consumed head packet first. Otherwise an idle recv sees
     * packets_ll != NULL and silently returns 0, but Linux netlink never
     * returns 0. Callers expect EAGAIN or nfl_die. */
    sock_update_recv_buffer(socket);
    if (!socket->packets_ll) {
        if (!socket->status_flags.blocking || flags.msg_dontwait) {
            errno = EAGAIN;
            return -1;
        }
        nfl_log("Blocking recv(/from/msg) on netlink socket without incoming data");
        nfl_block_or_exit((const nfl_sock_t *)socket);
        errno = EINTR;
        return -1;
    }

    // Source address: kernel-originated unicast -> {AF_NETLINK, pid=0, groups=0}.
    if (msg->msg_name) {
        const socklen_t want = (socklen_t)sizeof(struct sockaddr_nl);
        struct sockaddr_nl src = {
            .nl_family = AF_NETLINK,
            .nl_pad = 0,
            .nl_pid = 0,
            .nl_groups = 0,
        };
        const socklen_t copy_len = msg->msg_namelen < want ? msg->msg_namelen : want;
        memcpy(msg->msg_name, &src, copy_len);
        if (msg->msg_namelen < want) {
            msg->msg_flags |= MSG_TRUNC;
        }
        msg->msg_namelen = want;
    }

    const ssize_t amount_bytes_available = (ssize_t)sock_recv_buffer_bytes_available(socket);
    const ssize_t amount_bytes_read = socket_recv_iov(socket, msg->msg_iov, msg->msg_iovlen, flags.msg_peek);
    if (amount_bytes_available != amount_bytes_read) {
        msg->msg_flags |= MSG_TRUNC;
        if (!flags.msg_peek) {
            sock_clear_recv_buffer_and_load_next_packet(socket);
        }
    }

    if (flags.msg_trunc) {
        return amount_bytes_available;
    }
    return amount_bytes_read;
}
