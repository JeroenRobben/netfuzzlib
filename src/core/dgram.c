#include <netfuzzlib/callbacks.h>
#include <netfuzzlib/types.h>
#include "callback_wrapper.h"
#include "core.h"
#include "dgram.h"
#include "recv_buffer.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <linux/ipv6.h>

#include "addr.h"

// Set the 'default' remote address of a DGRAM sock
int connect_dgram(nfl_sock_full_t *sock, const nfl_addr_t *addr, const socklen_t addrlen) {
    if (addr == NULL || addr->s.sa_family == AF_UNSPEC) {
        if (addr && addrlen == 0) {
            errno = EINVAL;
            return -1;
        }
        if (sock->remote_addr) {
            free(sock->remote_addr);
            sock->remote_addr = NULL;
        }
        return 0;
    }
    assert(addr->s.sa_family == sock->domain);

    const socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);

    if (addrlen < correct_addrlen) {
        nfl_log("Connect called on dgram sock with invalid addrlen");
        errno = EINVAL;
        return -1;
    }

    nfl_addr_t *remote_addr = malloc(sizeof(nfl_addr_t));
    if (!remote_addr) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(remote_addr, addr, correct_addrlen);
    if (sock->remote_addr != NULL) {
        free(sock->remote_addr);
    }
    sock->remote_addr = remote_addr;

    if (!sock->local_addr) {
        if (autobind_udp(sock, addr) == -1) {
            free(sock->remote_addr);
            sock->remote_addr = NULL;
            return -1;
        }
    }
    nfl_log("connect() success: %s", sock_to_str(sock));
    return 0;
}

static void handle_recmvsg_pktinfo(struct msghdr *msg, const unsigned int device_index, nfl_addr_t *dest_address_packet_header, nfl_addr_t *device_addr) {
    const size_t cmsg_len_max = msg->msg_controllen;
    struct cmsghdr *my_cmsghdr = CMSG_FIRSTHDR(msg);
    // See RFC 3542
    if (!my_cmsghdr) {
        nfl_log("IP_PKTINFO or IPV6_PKTINFO asked, passed buffer to small, returning flag MSG_CTRUNC \n");
        msg->msg_flags |= MSG_CTRUNC;
    } else {
        size_t cmsg_len_used = 0;
        if (dest_address_packet_header->s.sa_family == AF_INET6) {
            if (cmsg_len_used + CMSG_SPACE(sizeof(struct in6_pktinfo)) > cmsg_len_max) {
                nfl_log("IPV6_PKTINFO asked, passed buffer to small, returning flag MSG_CTRUNC  \n");
                msg->msg_flags |= MSG_CTRUNC;
            } else {
                my_cmsghdr->cmsg_level = IPPROTO_IPV6;
                my_cmsghdr->cmsg_type = IPV6_PKTINFO;
                my_cmsghdr->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
                struct in6_pktinfo *pktinfo = (struct in6_pktinfo *)CMSG_DATA(my_cmsghdr);
                pktinfo->ipi6_ifindex = device_index;
                memcpy(&pktinfo->ipi6_addr, &((struct sockaddr_in6 *)dest_address_packet_header)->sin6_addr, sizeof(struct in6_addr));
                cmsg_len_used += CMSG_SPACE(sizeof(struct in6_pktinfo));
                msg->msg_controllen = cmsg_len_used;
            }
        } else if (dest_address_packet_header->s.sa_family == AF_INET) {
            if (cmsg_len_used + CMSG_SPACE(sizeof(struct in_pktinfo)) > cmsg_len_max) {
                nfl_log("IP_PKTINFO asked, passed buffer to small, returning flag MSG_CTRUNC  \n");
                msg->msg_flags |= MSG_CTRUNC;
            } else {
                my_cmsghdr->cmsg_level = IPPROTO_IP;
                my_cmsghdr->cmsg_type = IP_PKTINFO;
                my_cmsghdr->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
                struct in_pktinfo *pktinfo = (struct in_pktinfo *)CMSG_DATA(my_cmsghdr);
                pktinfo->ipi_ifindex = (int)device_index;
                pktinfo->ipi_addr.s_addr = ((struct sockaddr_in *)dest_address_packet_header)->sin_addr.s_addr;

                if (((struct sockaddr_in *)dest_address_packet_header)->sin_addr.s_addr != INADDR_ANY) {
                    pktinfo->ipi_spec_dst.s_addr = ((struct sockaddr_in *)dest_address_packet_header)->sin_addr.s_addr;
                } else {
                    pktinfo->ipi_spec_dst.s_addr = ((struct sockaddr_in *)device_addr)->sin_addr.s_addr;
                }
                cmsg_len_used += CMSG_SPACE(sizeof(struct in_pktinfo));
                msg->msg_controllen = cmsg_len_used;
            }
        }
    }
}

ssize_t recvmsg_dgram(nfl_sock_full_t *sock, struct msghdr *msg, const nfl_recv_flags flags) {
    sock_update_recv_buffer(sock);

    if (!sock->packets_ll) {
        if (!sock->status_flags.blocking || flags.msg_dontwait) {
            errno = EAGAIN;
            return -1;
        }
        nfl_log("Blocking recv(/from/msg) on sock without incoming data, %s", sock_to_str(sock));
        nfl_block_or_exit((const nfl_sock_t *)sock);
        errno = EINTR;
        return -1;
    }

    if (sock->status_flags.recv_pkt_info && sock->local_addr) {
        handle_recmvsg_pktinfo(msg, sock->packets_ll->device_index, &sock->packets_ll->local_addr, sock->local_addr);
    }

    const socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);
    if (msg->msg_name) {
        if (msg->msg_namelen < correct_addrlen) {
            nfl_log("recv{from/msg} call with passed sockaddr length too short");
            memcpy(msg->msg_name, &sock->packets_ll->remote_addr, msg->msg_namelen);
        } else {
            memcpy(msg->msg_name, &sock->packets_ll->remote_addr, correct_addrlen);
        }
        msg->msg_namelen = correct_addrlen;
    }

    const ssize_t amount_bytes_available = (ssize_t)sock_recv_buffer_bytes_available(sock);
    const ssize_t amount_bytes_read = socket_recv_iov(sock, msg->msg_iov, msg->msg_iovlen, flags.msg_peek);
    if (amount_bytes_available != amount_bytes_read) {
        msg->msg_flags |= MSG_TRUNC;
        if (!flags.msg_peek) {
            sock_clear_recv_buffer_and_load_next_packet(sock);
        }
    }

    if (flags.msg_trunc) {
        return amount_bytes_available;
    }
    return amount_bytes_read;
}

ssize_t sendmsg_dgram(nfl_sock_full_t *sock, const struct msghdr *msg) {
    nfl_addr_t receiver;
    if (msg->msg_name && msg->msg_namelen) {
        const socklen_t correct = get_socket_domain_addrlen(sock->domain);
        if (msg->msg_namelen < correct) {
            errno = EINVAL;
            return -1;
        }
        memcpy(&receiver, msg->msg_name, correct);
    } else if (sock->remote_addr) {
        memcpy(&receiver, sock->remote_addr, sizeof(nfl_addr_t));
    } else {
        errno = EDESTADDRREQ;
        return -1;
    }

    if (!sock->local_addr) {
        const int ret = autobind_udp(sock, &receiver);
        if (ret < 0) {
            nfl_log("Could not send data on %s to %s", sock_to_str(sock), sockaddr_to_str_static_alloc(&receiver));
            return -1;
        }
    }
    if (nfl_send_priv((const nfl_sock_t *)sock, &receiver, msg->msg_iov, msg->msg_iovlen) == NFL_CONN_CLOSED) {
        // Connected UDP peer reported gone (e.g. ICMP port-unreachable): async ECONNREFUSED.
        errno = ECONNREFUSED;
        return -1;
    }
    const ssize_t amount_bytes_sent = iov_count_bytes(msg->msg_iov, msg->msg_iovlen);

#ifdef NFL_DEBUG
    char sender_str[SOCKADDR_STR_MAX_LEN];
    char receiver_str[SOCKADDR_STR_MAX_LEN];
    sockaddr_to_str(sock->local_addr, sender_str, sizeof(sender_str));
    sockaddr_to_str(&receiver, receiver_str, sizeof(receiver_str));
    nfl_log("Sent %ld bytes | from: %s | to %s | %s", amount_bytes_sent, sender_str, receiver_str, sock_to_str(sock));
#endif
    return amount_bytes_sent;
}
