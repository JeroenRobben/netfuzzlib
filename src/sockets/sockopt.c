#include "sockopt.h"
#include "hooks/hooks.h"
#include "environment/network_env.h"
#include <netfuzzlib/module_api.h>
#include <errno.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <string.h>

#define WARN_CASE_GETSOCKOPT(level, param)                                                                                            \
    case ((param)):                                                                                                                   \
        nfl_log_warn("getsockopt | level: " #level " | option: " #param " | not relevant or unsupported by model. Silent ignoring."); \
        break

#define WARN_CASE_SETSOCKOPT(level, param)                                                                                            \
    case ((param)):                                                                                                                   \
        nfl_log_warn("setsockopt | level: " #level " | option: " #param " | not relevant or unsupported by model. Silent ignoring."); \
        break

int fcntl_nfl(nfl_sock_t *sock, int cmd, ...) {
    int ret = 0;
    va_list varargs;
    va_start(varargs, cmd);

    switch (cmd) {
        case F_GETFL:
            ret = sock->status_flags.blocking ? 0 : SOCK_NONBLOCK;
            break;
        case F_SETFL: {
            int flags = va_arg(varargs, int);
            if (flags != 0 && flags != SOCK_NONBLOCK) {
                nfl_log_warn("Got unsupported flags in fcntl F_SETL, only SOCK_NONBLOCK supported. Other flags ignored");
            }
            sock->status_flags.blocking = !(flags & SOCK_NONBLOCK);
            ret = 0;
            break;
        }
        case F_GETFD:
        case F_SETFD:
            ret = 0;
            break;
        case F_DUPFD:
        case F_DUPFD_CLOEXEC:
            ret = dup_nfl_sock(sock);
            break;
        default: {
            nfl_log_warn("Fcntl call with unsupported command. Silent ignore.");
            ret = 0;
            break;
        }
    }
    va_end(varargs);
    return ret;
}

int getsockopt_nfl(nfl_sock_t *sock, int level, int option_name, void *option_value, socklen_t *option_len) {
    if (level == IPPROTO_IP) {
        if (sock->domain != AF_INET) {
            nfl_log_warn("getsockopt with level IPPROTO_IP not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IP_PKTINFO):
            *((int *)option_value) = sock->status_flags.recv_pkt_info;
            *option_len = sizeof(sock->status_flags.recv_pkt_info);
            return 0;
        case (IP_OPTIONS): {
            socklen_t len = *option_len;
            if (len > sock->status_flags.ip_options_len) {
                len = sock->status_flags.ip_options_len;
            }
            memcpy(option_value, sock->status_flags.ip_options, len);
            *option_len = len;
            return 0;
        }
        }
    } else if (level == IPPROTO_IPV6) {
        if (sock->domain != AF_INET6) {
            nfl_log_warn("getsockopt with level IPPROTO_IPV6 not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IPV6_UNICAST_HOPS): {
            *((int *)option_value) = 64;
            *option_len = sizeof(int);
            return 0;
        }
        case (IPV6_PKTINFO):
        case (IPV6_RECVPKTINFO): {
            *((int *)option_value) = sock->status_flags.recv_pkt_info;
            *option_len = sizeof(sock->status_flags.recv_pkt_info);
            return 0;
        }
        }
    } else if (level == SOL_SOCKET) {
        switch (option_name) {
        case (SO_DOMAIN):
            *((int *)option_value) = sock->domain;
            *option_len = sizeof(sock->domain);
            return 0;
        case (SO_TYPE):
            *((int *)option_value) = sock->type;
            *option_len = sizeof(sock->type);
            return 0;
        case (SO_PROTOCOL):
            *((int *)option_value) = sock->protocol;
            *option_len = sizeof(sock->protocol);
            return 0;
        case (SO_ACCEPTCONN):
            *((int *)option_value) = sock->is_listening;
            *option_len = sizeof(int);
            return 0;
        case (SO_ERROR):
            *((int *)option_value) = 0;
            *option_len = sizeof(int);
            return 0;
        case (SO_RCVTIMEO):
            *((int *)option_value) = sock->status_flags.rcvtimeo;
            *option_len = sizeof(int);
            return 0;
        case (SO_SNDTIMEO):
            *((int *)option_value) = sock->status_flags.sndtimeo;
            *option_len = sizeof(int);
            return 0;
        }
    } else if (level == SOL_NETLINK) {
        if (sock->domain != AF_NETLINK) {
            nfl_log_warn("getsockopt with level SOL_NETLINK not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (NETLINK_LIST_MEMBERSHIPS):
            *((uint32_t *)option_value) = sock->local_addr ? ((struct sockaddr_nl *)sock->local_addr)->nl_groups : 0;
            *option_len = sizeof(uint32_t);
            return 0;
        }
    }

    getsockopt_print_unsupported_error(level, option_name);
    errno = EOPNOTSUPP;
    return -1;
}

int setsockopt_nfl(nfl_sock_t *sock, int level, int option_name, const void *option_value, socklen_t option_len) {
    if (level == SOL_SOCKET) {
        switch (option_name) {
        case (SO_RCVTIMEO):
            sock->status_flags.rcvtimeo = *((int *)option_value);
            return 0;
        case (SO_SNDTIMEO):
            sock->status_flags.sndtimeo = *((int *)option_value);
            return 0;
        }
    } else if (level == IPPROTO_IP) {
        if (sock->domain != AF_INET) {
            nfl_log_warn("setsockopt with level IPPROTO_IP not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IP_PKTINFO):
            sock->status_flags.recv_pkt_info = *((int *)option_value);
            return 0;
        case (SOCK_NONBLOCK):
            sock->status_flags.blocking = false;
            return 0;
        case (IP_OPTIONS): {
            if (option_len > sizeof(sock->status_flags.ip_options)) {
                nfl_log_warn("setsockopt IP_OPTIONS: option_len too large");
                return -1;
            }
            memcpy(sock->status_flags.ip_options, option_value, option_len);
            sock->status_flags.ip_options_len = option_len;
            return 0;
        }
        }
    } else if (level == IPPROTO_IPV6) {
        if (sock->domain != AF_INET6) {
            nfl_log_warn("setsockopt with level IPPROTO_IPV6 not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (SOCK_NONBLOCK):
            sock->status_flags.blocking = false;
            return 0;
        case (IPV6_RECVPKTINFO):
        case (IPV6_PKTINFO):
            sock->status_flags.recv_pkt_info = *((int *)option_value);
            return 0;
        }
    } else if (level == SOL_NETLINK) {
        if (sock->domain != AF_NETLINK) {
            nfl_log_warn("setsockopt with level SOL_NETLINK not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        struct sockaddr_nl *nl_socket = (struct sockaddr_nl *)sock->local_addr;
        switch (option_name) {
        case (NETLINK_ADD_MEMBERSHIP):
            if (nl_socket)
                nl_socket->nl_groups |= *(int32_t *)option_value;
            return 0;
        case (NETLINK_DROP_MEMBERSHIP):
            if (nl_socket)
                nl_socket->nl_groups = nl_socket->nl_groups & ~(*(int32_t *)option_value);
            return 0;
        }
    }
    setsockopt_print_unsupported_error(level, option_name);
    return 0;
}

void getsockopt_print_unsupported_error(int level, int option_name) {
    // We want nfl_log_warn to be called once for every option_name in case of using klee_warning_once, so as
    // far as I know we need this bulky construct
    if (level == SOL_SOCKET) {
        switch (option_name) {
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_ATTACH_FILTER);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_BINDTODEVICE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_BROADCAST);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_BSDCOMPAT);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_DEBUG);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_DETACH_FILTER);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_DONTROUTE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_INCOMING_CPU);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_INCOMING_NAPI_ID);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_KEEPALIVE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_LINGER);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_LOCK_FILTER);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_MARK);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_OOBINLINE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PASSCRED);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PASSSEC);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PEEK_OFF);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PEERCRED);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PEERSEC);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_RCVBUF);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_RCVBUFFORCE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_RCVLOWAT);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_SNDLOWAT);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_RCVTIMEO);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_SNDTIMEO);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_PRIORITY);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_REUSEADDR);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_REUSEPORT);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_RXQ_OVFL);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_SELECT_ERR_QUEUE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_SNDBUF);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_SNDBUFFORCE);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_TIMESTAMP);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_TIMESTAMPNS);
            WARN_CASE_GETSOCKOPT(SOL_SOCKET, SO_BUSY_POLL);
        default:
            nfl_log_warn("getsockopt | level: SOL_SOCKET | option: %d "
                         "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                         option_name);
        }
    } else if (level == SOL_NETLINK) {
        switch (option_name) {
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_PKTINFO);
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_BROADCAST_ERROR);
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_NO_ENOBUFS);
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_CAP_ACK);
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_EXT_ACK);
            WARN_CASE_GETSOCKOPT(SOL_NETLINK, NETLINK_GET_STRICT_CHK);
        default:
            nfl_log_warn("getsockopt | level: SOL_NETLINK | option: %d "
                         "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                         option_name);
        }
    } else if (level == IPPROTO_IP) {
        switch (option_name) {
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_ADD_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_BLOCK_SOURCE);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_DROP_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_FREEBIND);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_HDRINCL);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MSFILTER);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MTU);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MTU_DISCOVER);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MULTICAST_ALL);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MULTICAST_IF);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MULTICAST_LOOP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_MULTICAST_TTL);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_NODEFRAG);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_OPTIONS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_PASSSEC);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RECVERR);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RECVOPTS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RECVORIGDSTADDR);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RECVTOS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RECVTTL);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_RETOPTS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_ROUTER_ALERT);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_TOS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_TRANSPARENT);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_TTL);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, IP_UNBLOCK_SOURCE);
            WARN_CASE_GETSOCKOPT(IPPROTO_IP, SO_PEERSEC);
        default:
            nfl_log_warn("getsockopt | level: IPPROTO_IP | option: %d "
                         "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                         option_name);
        }
    } else if (level == IPPROTO_IPV6) {
        switch (option_name) {
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_MTU);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_MTU_DISCOVER);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_HOPS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_IF);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_LOOP);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_RTHDR);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_AUTHHDR);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_DSTOPTS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_HOPOPTS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_HOPLIMIT);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_RECVERR);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_ROUTER_ALERT);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_UNICAST_HOPS);
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_V6ONLY);
#ifdef IPV6_FLOWINFO
            WARN_CASE_GETSOCKOPT(IPPROTO_IPV6, IPV6_FLOWINFO);
#endif
        default:
            nfl_log_warn("getsockopt | level: IPPROTO_IPV6 | option: %d "
                         "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                         option_name);
        }
    } else {
        nfl_log_warn("getsockopt | level: %d | option: %d "
                     "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                     level, option_name);
    }
}

void setsockopt_print_unsupported_error(int level, int option_name) {
    // We want nfl_log_warn to be called once for every option_name, so as
    // far as I know we need this bulky construct
    if (level == SOL_SOCKET) {
        switch (option_name) {
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_ATTACH_FILTER);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_ATTACH_REUSEPORT_CBPF);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_ATTACH_REUSEPORT_EBPF);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_BINDTODEVICE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_BROADCAST);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_BSDCOMPAT);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_DEBUG);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_DETACH_FILTER);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_DOMAIN);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_ERROR);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_DONTROUTE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_INCOMING_CPU);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_INCOMING_NAPI_ID);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_KEEPALIVE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_LINGER);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_LOCK_FILTER);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_MARK);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_OOBINLINE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PASSCRED);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PASSSEC);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PEEK_OFF);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PEERCRED);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PEERSEC);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PRIORITY);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_PROTOCOL);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_RCVBUF);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_RCVBUFFORCE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_RCVLOWAT);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_SNDLOWAT);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_RCVTIMEO);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_SNDTIMEO);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_REUSEADDR);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_REUSEPORT);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_RXQ_OVFL);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_SELECT_ERR_QUEUE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_SNDBUF);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_SNDBUFFORCE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_TIMESTAMP);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_TIMESTAMPNS);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_TYPE);
            WARN_CASE_SETSOCKOPT(SOL_SOCKET, SO_BUSY_POLL);
        default:
            nfl_log_warn("setsockopt | level: SOL_SOCKET | option: %d "
                         "not relevant or unsupported by model. Silent ignoring.",
                         option_name);
        }
    } else if (level == SOL_NETLINK) {
        switch (option_name) {
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_PKTINFO);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_BROADCAST_ERROR);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_NO_ENOBUFS);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_LISTEN_ALL_NSID);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_CAP_ACK);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_EXT_ACK);
            WARN_CASE_SETSOCKOPT(SOL_NETLINK, NETLINK_GET_STRICT_CHK);
        default:
            nfl_log_warn("setsockopt | level: SOL_NETLINK | option: %d "
                         "not relevant or unsupported by model. Silent ignoring.",
                         option_name);
        }
    } else if (level == IPPROTO_IP) {
        switch (option_name) {
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_ADD_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_ADD_SOURCE_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_BLOCK_SOURCE);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_DROP_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_DROP_SOURCE_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_FREEBIND);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_HDRINCL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MSFILTER);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MTU);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MTU_DISCOVER);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MULTICAST_ALL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MULTICAST_IF);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MULTICAST_LOOP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_MULTICAST_TTL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_NODEFRAG);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_OPTIONS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_PASSSEC);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RECVERR);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RECVOPTS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RECVORIGDSTADDR);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RECVTOS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RECVTTL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_RETOPTS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_ROUTER_ALERT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_TOS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_TRANSPARENT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_TTL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_UNBLOCK_SOURCE);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, SO_PEERSEC);
        default:
            nfl_log_warn("setsockopt | level: IPPROTO_IP | option: %d "
                         "unsupported by model. Silent ignoring.",
                         option_name);
        }
    } else if (level == IPPROTO_IPV6) {
        switch (option_name) {
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_ADDRFORM);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_ADD_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_DROP_MEMBERSHIP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_MTU);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_MTU_DISCOVER);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_HOPS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_IF);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_MULTICAST_LOOP);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_RTHDR);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_AUTHHDR);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_DSTOPTS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_HOPOPTS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_HOPLIMIT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_RECVERR);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_ROUTER_ALERT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_UNICAST_HOPS);
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_V6ONLY);
#ifdef IPV6_FLOWINFO
            WARN_CASE_SETSOCKOPT(IPPROTO_IPV6, IPV6_FLOWINFO);
#endif
        default:
            nfl_log_warn("setsockopt | level: IPPROTO_IPV6 | option: %d "
                         "| not relevant or unsupported by model. Silent ignoring.",
                         option_name);
        }
    } else {
        nfl_log_warn("setsockopt | level: %d | option: %d "
                     "| not relevant or unsupported by model. Silent ignoring.",
                     level, option_name);
    }
}