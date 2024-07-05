#include "sockets_rtnetlink.h"
#include "lib/libnl/libnl.h"
#include "sockets_util.h"
#include "hooks/hooks.h"
#include "environment/interfaces.h"
#include <arpa/inet.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if_arp.h>
#include <string.h>

static void free_netlink_msgs(netlink_msg_ll *msgs) {
    while (msgs) {
        netlink_msg_ll *next = msgs->next;
        nlmsg_free(msgs->msg);
        free(msgs);
        msgs = next;
    }
}

static nfl_pkt *netlink_msg_to_network_packet(netlink_msg_ll *netlink_msg_ll_entry) {
    size_t length = nlmsg_hdr(netlink_msg_ll_entry->msg)->nlmsg_len;
    nfl_pkt *packet = nfl_alloc_pkt(NLMSG_ALIGN(length));
    if (!packet) {
        errno = ENOBUFS;
        return NULL;
    }
    memcpy(packet->iov.iov_base, nlmsg_hdr(netlink_msg_ll_entry->msg), length);
    return packet;
}

static int send_netlink_done(nfl_sock_t *socket, __u32 pid, __u32 seq) {
    struct nlmsghdr donehdr;
    memset(&donehdr, 0, sizeof(struct nlmsghdr));
    donehdr.nlmsg_len = sizeof(struct nlmsghdr) + sizeof(int);
    //man 7 netlink says to not set the NLM_F_MULTI on NLMSG_DONE messages.
    //However, the Linux kernel implementation seems to set it nevertheless (strace ip link) hence we follow the behaviour of the kernel.
    donehdr.nlmsg_flags = NLM_F_MULTI;
    donehdr.nlmsg_type = NLMSG_DONE;
    donehdr.nlmsg_pid = pid;
    donehdr.nlmsg_seq = seq;
    nfl_pkt *packet = nfl_alloc_pkt(NLMSG_ALIGN(donehdr.nlmsg_len));
    if (!packet) {
        return -1;
    }
    memcpy(packet->iov.iov_base, &donehdr, sizeof(struct nlmsghdr));
    nfl_log_debug("Adding netlink NLMSG_DONE message");
    sock_append_packet(socket, packet);
    return 0;
}

static int send_netlink_msgs(nfl_sock_t *socket, netlink_msg_ll *msgs, bool multipart) {
    nfl_pkt *packet;
    netlink_msg_ll *msg_ll;

    for (msg_ll = msgs; msg_ll; msg_ll = msg_ll->next) {
        if (multipart) {
            nlmsg_hdr(msg_ll->msg)->nlmsg_flags |= NLM_F_MULTI;
        }
        packet = netlink_msg_to_network_packet(msg_ll);
        if (!packet) {
            errno = ENOBUFS;
            return -1;
        }
        sock_append_packet(socket, packet);
    }

    if (multipart) { //Add NLMSG_DONE message
        int err = send_netlink_done(socket, nlmsg_hdr(msgs->msg)->nlmsg_pid, nlmsg_hdr(msgs->msg)->nlmsg_seq);
        if (err) {
            errno = ENOBUFS;
            return -1;
        }
    }
    return 0;
}

static inline int ipv4_subnet_to_prefixlen(struct sockaddr_in *addr) {
    in_addr_t n = addr->sin_addr.s_addr;
    int i = 0;

    while (n > 0) {
        n = n >> 1;
        i++;
    }
    return i;
}

static struct nl_msg *address_to_nl_message(struct nlmsghdr *request, nfl_l3_iface_t *address) {
    int ifa_f_permanent_flag = IFA_F_PERMANENT;
    struct ifaddrmsg ifaddr;

    struct nl_msg *netlink_msg = nlmsg_alloc();

    if (!netlink_msg) {
        errno = ENOBUFS;
        return NULL;
    }

    struct ifa_cacheinfo cacheinfo;
    cacheinfo.ifa_prefered = 3000;
    cacheinfo.ifa_valid = 3000;
    cacheinfo.cstamp = 10000;
    cacheinfo.tstamp = 20000;

    int err = !nlmsg_put(netlink_msg, request->nlmsg_pid, request->nlmsg_seq, RTM_NEWADDR, 0, 0);
    memset(&ifaddr, 0, sizeof(struct ifaddrmsg));
    ifaddr.ifa_index = address->parent_l2_iface->index;
    ifaddr.ifa_family = address->addr->s.sa_family;
    ifaddr.ifa_flags = ifa_f_permanent_flag;

    if (address->addr->s.sa_family == AF_INET) {
        struct sockaddr_in *ipv4_address = (struct sockaddr_in *)address->addr;
        ifaddr.ifa_prefixlen = ipv4_subnet_to_prefixlen((struct sockaddr_in *)address->netmask);

        if (ipv4_address->sin_addr.s_addr == htonl(INADDR_LOOPBACK)) {
            ifaddr.ifa_scope = RT_SCOPE_HOST;
        } else
            ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;
        err = nlmsg_append(netlink_msg, &ifaddr, sizeof(struct ifaddrmsg), NLMSG_ALIGNTO);

        err |= nla_put(netlink_msg, IFA_LOCAL, sizeof(in_addr_t), &ipv4_address->sin_addr.s_addr);
        err |= nla_put(netlink_msg, IFA_ADDRESS, sizeof(in_addr_t), &ipv4_address->sin_addr.s_addr);
        struct sockaddr_in broadcast_addr;
        get_l3_iface_broadcast_addr(address, &broadcast_addr);
        err |= nla_put(netlink_msg, IFA_BROADCAST, sizeof(in_addr_t), &broadcast_addr.sin_addr.s_addr);
        err |= nla_put(netlink_msg, IFA_LABEL, (int)strlen(address->parent_l2_iface->name), &address->parent_l2_iface->name);
        err |= nla_put(netlink_msg, IFA_FLAGS, sizeof(ifa_f_permanent_flag), &ifa_f_permanent_flag);
        err |= nla_put(netlink_msg, IFA_CACHEINFO, sizeof(struct ifa_cacheinfo), &cacheinfo);
    } else if (address->addr->s.sa_family == AF_INET6) {
        struct sockaddr_in6 *ipv6_address = (struct sockaddr_in6 *)address->addr;
        ifaddr.ifa_prefixlen = address->prefix;

        if (IN6_IS_ADDR_LOOPBACK(&ipv6_address->sin6_addr))
            ifaddr.ifa_scope = RT_SCOPE_HOST;
        else if (IN6_IS_ADDR_LINKLOCAL(&ipv6_address->sin6_addr))
            ifaddr.ifa_scope = RT_SCOPE_LINK;
        else
            ifaddr.ifa_scope = RT_SCOPE_UNIVERSE;

        err |= nlmsg_append(netlink_msg, &ifaddr, sizeof(struct ifaddrmsg), NLMSG_ALIGNTO);
        err |= nla_put(netlink_msg, IFA_ADDRESS, sizeof(struct in6_addr), &ipv6_address->sin6_addr);
        err |= nla_put(netlink_msg, IFA_FLAGS, sizeof(ifa_f_permanent_flag), &ifa_f_permanent_flag);
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

static int handle_getaddr(nfl_sock_t *socket, struct nlmsghdr *request, ssize_t len) {
    if (!(request->nlmsg_flags & NLM_F_REQUEST) || !(request->nlmsg_flags & NLM_F_ROOT)) {
        //TODO send error
        return -1;
    }
    int filter_domain = 0;
    if (NLMSG_PAYLOAD(request, len) >= sizeof(struct rtgenmsg)) {
        filter_domain = ((struct rtgenmsg *)NLMSG_DATA(request))->rtgen_family;
    }
    nfl_log_debug("Handling Netlink GETADDR request, filter_domain: %d", filter_domain);

    nfl_l2_iface_t *device;
    nfl_l3_iface_t *address;
    struct netlink_msg_ll *responses = NULL;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        device = get_l2_iface_by_index(i);
        if (!device)
            continue;
        for (address = device->l3_interfaces; address; address = address->next) {
            if (filter_domain && filter_domain != address->addr->s.sa_family) {
                continue;
            }
            struct nl_msg *msg = address_to_nl_message(request, address);
            if (!msg) {
                //TODO print error;
                continue;
            }
            struct netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
            if (!response) {
                nlmsg_free(msg);
                errno = ENOBUFS;
                continue; //TODO HANDLE
            }

            nfl_log_debug("GETADDR matched: %s", network_device_address_to_string(address));
            response->msg = msg;
            response->next = responses;
            responses = response;
        }
    }
    if (responses) {
        nfl_log_debug("GETADDR sending response(s)");
        send_netlink_msgs(socket, responses, true);
        free_netlink_msgs(responses);
    } else {
        nfl_log_debug("GETADDR no match, not sending response(s)");
    }
    return 0;
}

static struct nl_msg *device_to_nl_message(struct nlmsghdr *request, nfl_l2_iface_t *device) {
    struct nl_msg *netlink_message = nlmsg_alloc();
    if (!netlink_message) {
        return NULL;
    }
    int err = !nlmsg_put(netlink_message, request->nlmsg_pid, request->nlmsg_seq, RTM_NEWLINK, 0, 0);
    if (err) {
        nlmsg_free(netlink_message);
        return NULL;
    }
    struct ifinfomsg ifinfo;
    memset(&ifinfo, 0, sizeof(struct ifinfomsg));
    ifinfo.ifi_family = AF_UNSPEC;
    ifinfo.ifi_type = l2_iface_is_loopback(device) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
    ifinfo.ifi_index = (int)device->index;
    ifinfo.ifi_flags = device->flags;
    ifinfo.ifi_change = 0xFFFFFFFF;
    err = nlmsg_append(netlink_message, &ifinfo, sizeof(struct ifinfomsg), NLMSG_ALIGNTO);

    err |= nla_put(netlink_message, IFLA_ADDRESS, sizeof(device->hw_addr), &device->hw_addr);
    err |= nla_put(netlink_message, IFLA_BROADCAST, sizeof(device->hw_broadcast_addr), &device->hw_broadcast_addr);
    err |= nla_put(netlink_message, IFLA_IFNAME, (int)(strlen(device->name) + sizeof('\0')), &device->name);
    err |= nla_put(netlink_message, IFLA_MTU, sizeof(device->mtu), &device->mtu);
    err |= nla_put(netlink_message, IFLA_QDISC, sizeof("noqueue"), "noqueue");

    struct rtnl_link_stats stats;
    memset(&stats, 0, sizeof(struct rtnl_link_stats));
    err |= nla_put(netlink_message, IFLA_STATS, sizeof(struct rtnl_link_stats), &stats);
    if (err) {
        nlmsg_free(netlink_message);
        return NULL;
    }
    return netlink_message;
}

static struct rtattr *find_attribute(struct nlmsghdr *hdr, unsigned short rta_type) {
    struct rtmsg *rt_msg = (struct rtmsg *)NLMSG_DATA(hdr);
    int len = RTM_PAYLOAD(hdr);
    struct rtattr *rta;

    // loop & get every attribute
    for (rta = RTM_RTA(rt_msg); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == rta_type) {
            return rta;
        }
    }
    return NULL;
}

static void handle_getlink(nfl_sock_t *socket, struct nlmsghdr *request, ssize_t len) {
    struct ifinfomsg *ifinfo = NLMSG_DATA(request);
    bool match_single_device = request->nlmsg_flags & NLM_F_MATCH;
    nfl_l2_iface_t *device;

    struct netlink_msg_ll *responses = NULL;
    struct rtattr *rta_name_filter = ifinfo->ifi_index == 0 ? find_attribute(request, IFLA_IFNAME) : NULL;

    nfl_log_debug("Handling Netlink GETLINK request, match_single_device: %d, rta_name_filter set: %d", match_single_device, rta_name_filter);
    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        device = get_l2_iface_by_index(i);
        if (!device)
            continue;
        nfl_log_debug("GETLINK trying to match device: %s", device->name);
        if (match_single_device) {
            if (ifinfo->ifi_index > 0 && device->index != ifinfo->ifi_index) { // Filter by device index
                nfl_log_debug("GETLINK skipping device %s, index %d not equal to requested index %d", device->name, device->index, ifinfo->ifi_index);
                continue;
            }
            if (ifinfo->ifi_index == 0 && rta_name_filter &&
                strncmp(RTA_DATA(rta_name_filter), device->name,
                        RTA_PAYLOAD(rta_name_filter)) != 0) { // Filter by device name
                nfl_log_debug("GETLINK skipping device %s, name not equal to requested name: %s", device->name, RTA_DATA(rta_name_filter));
                continue;
            }
        }
        nfl_log_debug("GETLINK including device: %s", device->name);
        struct nl_msg *msg = device_to_nl_message(request, device);
        if (!msg) {
            nfl_log_warn("GETLINK device_to_nl_message returned error");
            //TODO print error;
            continue;
        }
        struct netlink_msg_ll *response = calloc(1, sizeof(netlink_msg_ll));
        if (!response) {
            nfl_log_warn("GETLINK could not allocate response");
            nlmsg_free(msg);
            errno = ENOBUFS;
            continue; //TODO HANDLE
        }
        response->msg = msg;
        response->next = responses;
        responses = response;
    }
    if (responses) {
        nfl_log_debug("GETLINK sending response(s)");
        send_netlink_msgs(socket, responses, true);
        free_netlink_msgs(responses);
    } else {
        nfl_log_debug("GETLINK no match, no response sent.");
    }
}

static void handle_getneigh(nfl_sock_t *socket, struct nlmsghdr *hdr, ssize_t len) {
    struct ndmsg *msg = NLMSG_DATA(hdr);
}

static void send_ack(nfl_sock_t *socket, struct nlmsghdr *hdr) {
    struct nl_msg *netlink_msg = nlmsg_alloc();
    if (!netlink_msg)
        return;
    int err = !nlmsg_put(netlink_msg, hdr->nlmsg_pid, hdr->nlmsg_seq, NLMSG_ERROR, 0, 0);
    if (err) {
        nlmsg_free(netlink_msg);
        return;
    }
    struct nlmsgerr err_message;
    memset(&err_message, 0, sizeof(struct nlmsgerr));
    err_message.error = 0; //ACK
    memcpy(&err_message.msg, hdr, sizeof(struct nlmsghdr));
    err = nlmsg_append(netlink_msg, &err_message, sizeof(struct nlmsgerr), NLMSG_ALIGNTO);
    if (err) {
        nlmsg_free(netlink_msg);
        return;
    }

    netlink_msg_ll *msg_ll = calloc(1, sizeof(netlink_msg_ll));
    if (!msg_ll) {
        nlmsg_free(netlink_msg);
        return;
    }
    msg_ll->msg = netlink_msg;
    send_netlink_msgs(socket, msg_ll, false);
    free_netlink_msgs(msg_ll);
}

ssize_t sendmsg_netlink(nfl_sock_t *socket, const struct msghdr *msg, int flags) {
    if (msg->msg_iovlen <= 0)
        return -1;

    ssize_t bytes_processed = 0;
    struct iovec *iov;
    size_t iov_array_offset;
    for (iov_array_offset = 0; iov_array_offset < msg->msg_iovlen; iov_array_offset++) {
        iov = &msg->msg_iov[iov_array_offset];
        ssize_t length = (ssize_t)iov->iov_len;
        bytes_processed += length;
        struct nlmsghdr *hdr;

        for (hdr = iov->iov_base; NLMSG_OK(hdr, length); hdr = NLMSG_NEXT(hdr, length)) {
            if (hdr->nlmsg_flags & NLM_F_MULTI) {
                nfl_log_warn("Got Netlink multipart message, not applicable for message request types supported by model. Message ignored.");
                continue;
            }

            if ((hdr->nlmsg_flags & NLM_F_ACK) || (hdr->nlmsg_flags & NLM_F_ECHO)) {
                send_ack(socket, hdr);
            }

            switch (hdr->nlmsg_type) {
            case (RTM_GETADDR):
                handle_getaddr(socket, hdr, length);
                continue;
            case (RTM_GETLINK):
                handle_getlink(socket, hdr, length);
                continue;
            case (RTM_GETNEIGH):
                handle_getneigh(socket, hdr, length);
                continue;
            default:
                nfl_log_debug("Got unsupported netlink message, type: %d. Message ignored.\n", hdr->nlmsg_type);
                continue;
            }
        }
    }
    return bytes_processed;
}

ssize_t recvmsg_netlink(nfl_sock_t *socket, struct msghdr *msg, int flags) {
    if (!socket->packets_ll) {
        if (!socket->status_flags.blocking || IS_FLAG_SET(flags, MSG_DONTWAIT)) {
            errno = EAGAIN;
            return -1;
        } else {
            nfl_log_fatal("Blocking recv(/from/msg) on netlink socket without incoming data");
            nfl_end_priv();
        }
    }

    if (msg->msg_name) {
        if (msg->msg_namelen < sizeof(struct sockaddr_nl)) {
            nfl_log_error("recv{from/msg} call to netlink with passed sockaddr length too short");
            return -1;
        } else {
            struct sockaddr_nl *nl_addr = msg->msg_name;
            nl_addr->nl_pid = 0;
            nl_addr->nl_groups = 0;
            nl_addr->nl_family = NETLINK_ROUTE;
            nl_addr->nl_pad = 0;
        }
        msg->msg_namelen = sizeof(struct sockaddr_nl);
    }

    ssize_t amount_bytes_available = (ssize_t)sock_recv_buffer_bytes_available(socket);
    ssize_t amount_bytes_read = socket_recv_iov(socket, msg->msg_iov, msg->msg_iovlen, IS_FLAG_SET(flags, MSG_PEEK));
    if (amount_bytes_available != amount_bytes_read) {
        msg->msg_flags |= MSG_TRUNC;
        if (!IS_FLAG_SET(flags, MSG_PEEK)) {
            sock_clear_recv_buffer_and_load_next_packet(socket);
        }
    }

    if (IS_FLAG_SET(flags, MSG_TRUNC)) {
        return amount_bytes_available;
    }
    return amount_bytes_read;
}
