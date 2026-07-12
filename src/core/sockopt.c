#include "sockopt.h"
#include "fd_table.h"
#include "network_env.h"
#include "handlers.h"
#include <netfuzzlib/callbacks.h>
#include <errno.h>
#include <linux/netlink.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#define WARN_CASE_GETSOCKOPT(level, param)                                                                                            \
    case ((param)):                                                                                                                   \
        nfl_log("getsockopt | level: " #level " | option: " #param " | not relevant or unsupported by model. Silent ignoring."); \
        break

#define WARN_CASE_SETSOCKOPT(level, param)                                                                                            \
    case ((param)):                                                                                                                   \
        nfl_log("setsockopt | level: " #level " | option: " #param " | not relevant or unsupported by model. Silent ignoring."); \
        break

int fcntl_nfl(nfl_sock_full_t *sock, const int cmd, void *argp) {
    switch (cmd) {
    case F_GETFL:
        // Linux: F_GETFL on a socket returns access mode (O_RDWR) OR'd with status flags.
        return O_RDWR | (sock->status_flags.blocking ? 0 : O_NONBLOCK);
    case F_SETFL: {
        const int flags = (int)(intptr_t)argp;
        if ((flags & ~(O_NONBLOCK | O_RDWR | O_RDONLY | O_WRONLY | O_ACCMODE)) != 0) {
            nfl_log("Unsupported flags in fcntl F_SETFL, only O_NONBLOCK is honored.");
        }
        sock->status_flags.blocking = !(flags & O_NONBLOCK);
        return 0;
    }
    case F_GETFD:
    case F_SETFD:
        return 0;
    case F_DUPFD:
    case F_DUPFD_CLOEXEC: {
        const int min_fd = (int)(intptr_t)argp;
        if (min_fd < 0 || min_fd >= NFL_FD_TABLE_SIZE) {
            errno = EINVAL;
            return -1;
        }
        const int fd = get_available_fd_from(min_fd);
        if (fd < 0) {
            errno = EMFILE;
            return -1;
        }
        fd_table_set(fd, sock);
        return fd;
    }
    default:
        nfl_log("Fcntl call with unsupported command. Silent ignore.");
        return 0;
    }
}

// Helper: write an int option, requiring the caller's buffer be large enough.
static int getsockopt_int(int value, void *option_value, socklen_t *option_len) {
    if (*option_len < sizeof(int)) {
        errno = EINVAL;
        return -1;
    }
    *((int *)option_value) = value;
    *option_len = sizeof(int);
    return 0;
}

int getsockopt_nfl(const nfl_sock_full_t *sock, const int level, const int option_name, void *option_value, socklen_t *option_len) {
    if (!option_value || !option_len) {
        errno = EFAULT;
        return -1;
    }
    if (level == IPPROTO_IP) {
        if (sock->domain != AF_INET) {
            nfl_log("getsockopt with level IPPROTO_IP not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IP_PKTINFO):
            return getsockopt_int(sock->status_flags.recv_pkt_info, option_value, option_len);
        case (IP_OPTIONS): {
            socklen_t len = *option_len;
            if (len > sock->status_flags.ip_options_len) {
                len = sock->status_flags.ip_options_len;
            }
            memcpy(option_value, sock->status_flags.ip_options, len);
            *option_len = len;
            return 0;
        }
        default:
            break;
        }
    } else if (level == IPPROTO_IPV6) {
        if (sock->domain != AF_INET6) {
            nfl_log("getsockopt with level IPPROTO_IPV6 not matching sock domain");
            errno = EOPNOTSUPP;
            return -1;
        }
        switch (option_name) {
        case (IPV6_UNICAST_HOPS):
            return getsockopt_int(64, option_value, option_len);
        case (IPV6_PKTINFO):
        case (IPV6_RECVPKTINFO):
            return getsockopt_int(sock->status_flags.recv_pkt_info, option_value, option_len);
        default:
            break;
        }
    } else if (level == SOL_SOCKET) {
        switch (option_name) {
        case (SO_DOMAIN):
            return getsockopt_int(sock->domain, option_value, option_len);
        case (SO_TYPE):
            return getsockopt_int(sock->type, option_value, option_len);
        case (SO_PROTOCOL):
            return getsockopt_int(sock->protocol, option_value, option_len);
        case (SO_ACCEPTCONN):
            return getsockopt_int(sock->is_listening, option_value, option_len);
        case (SO_ERROR):
            return getsockopt_int(0, option_value, option_len);
        case (SO_RCVTIMEO):
            if (*option_len < sizeof(struct timeval)) { errno = EINVAL; return -1; }
            *((struct timeval *)option_value) = sock->status_flags.rcvtimeo;
            *option_len = sizeof(struct timeval);
            return 0;
        case (SO_SNDTIMEO):
            if (*option_len < sizeof(struct timeval)) { errno = EINVAL; return -1; }
            *((struct timeval *)option_value) = sock->status_flags.sndtimeo;
            *option_len = sizeof(struct timeval);
            return 0;
        /* Pair with the setsockopt entries above: we don't track an actual
         * buffer size, so report a plausible default. 65536 matches the
         * loopback/ unix-style minimum on Linux. */
        case (SO_RCVBUF):
        case (SO_SNDBUF):
            return getsockopt_int(65536, option_value, option_len);
        default:
            break;
        }
    } else if (level == SOL_NETLINK) {
        if (sock->domain != AF_NETLINK) {
            nfl_log("getsockopt with level SOL_NETLINK not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (NETLINK_LIST_MEMBERSHIPS): {
            if (*option_len < sizeof(uint32_t)) {
                errno = EINVAL;
                return -1;
            }
            const uint32_t groups = sock->local_addr ? ((struct sockaddr_nl *)sock->local_addr)->nl_groups : 0;
            *((uint32_t *)option_value) = groups;
            *option_len = sizeof(uint32_t);
            return 0;
        }
        default:
            break;
        }
    }

    getsockopt_print_unsupported_error(level, option_name);
    errno = ENOPROTOOPT;
    return -1;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
int setsockopt_nfl(nfl_sock_full_t *sock, const int level, const int option_name, const void *option_value, const socklen_t option_len) {
    if (!option_value) {
        errno = EFAULT;
        return -1;
    }
    if (level == SOL_SOCKET) {
        switch (option_name) {
        case (SO_RCVTIMEO):
            if (option_len < sizeof(struct timeval)) { errno = EINVAL; return -1; }
            sock->status_flags.rcvtimeo = *((const struct timeval *)option_value);
            return 0;
        case (SO_SNDTIMEO):
            if (option_len < sizeof(struct timeval)) { errno = EINVAL; return -1; }
            sock->status_flags.sndtimeo = *((const struct timeval *)option_value);
            return 0;
        case (SO_RCVBUF):
        case (SO_SNDBUF):
        case (SO_RCVBUFFORCE):
        case (SO_SNDBUFFORCE):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            return 0;
        case (SO_REUSEADDR):
        case (SO_REUSEPORT):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            return 0;
        case (SO_KEEPALIVE):
        case (SO_BROADCAST):
        case (SO_DONTROUTE):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            return 0;
        case (SO_LINGER):
            if (option_len < (socklen_t)(2 * sizeof(int))) {
                errno = EINVAL;
                return -1;
            }
            return 0;
        default:
            break;
        }
    } else if (level == IPPROTO_IP) {
        if (sock->domain != AF_INET) {
            nfl_log("setsockopt with level IPPROTO_IP not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IP_PKTINFO):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            sock->status_flags.recv_pkt_info = *((const int *)option_value);
            return 0;
        case (IP_OPTIONS): {
            if (option_len > sizeof(sock->status_flags.ip_options)) {
                nfl_log("setsockopt IP_OPTIONS: option_len too large");
                return -1;
            }
            memcpy(sock->status_flags.ip_options, option_value, option_len);
            sock->status_flags.ip_options_len = option_len;
            return 0;
        }
        case (IP_MULTICAST_LOOP):
        case (IP_MULTICAST_TTL):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            return 0;
        case (IP_MULTICAST_IF):
            if (option_len == 0) { errno = EINVAL; return -1; }
            return 0;
        case (IP_TOS):
        case (IP_MTU_DISCOVER):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            return 0;
        default:
            break;
        }
    } else if (level == IPPROTO_IPV6) {
        if (sock->domain != AF_INET6) {
            nfl_log("setsockopt with level IPPROTO_IPV6 not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (IPV6_RECVPKTINFO):
        case (IPV6_PKTINFO):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            sock->status_flags.recv_pkt_info = *((const int *)option_value);
            return 0;
        case (IPV6_V6ONLY):
            if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
            sock->status_flags.v6only = (*((const int *)option_value) != 0);
            return 0;
        default:
            break;
        }
    } else if (level == IPPROTO_TCP) {
        if (option_len < sizeof(int)) { errno = EINVAL; return -1; }
        return 0;
    } else if (level == SOL_NETLINK) {
        if (sock->domain != AF_NETLINK) {
            nfl_log("setsockopt with level SOL_NETLINK not matching sock domain");
            errno = EINVAL;
            return -1;
        }
        switch (option_name) {
        case (NETLINK_ADD_MEMBERSHIP):
        case (NETLINK_DROP_MEMBERSHIP): {
            if (option_len < sizeof(int)) {
                errno = EINVAL;
                return -1;
            }
            const int group = *(const int *)option_value;
            // Kernel: optval is a 1-based group number. The bitmask bit is (1 << (group - 1)).
            if (group <= 0 || group > 32) {
                errno = EINVAL;
                return -1;
            }
            if (!sock->local_addr) {
                // Real kernel auto-binds the socket to a unique nl_pid before joining.
                errno = ENOTCONN;
                return -1;
            }
            struct sockaddr_nl *nl_socket = (struct sockaddr_nl *)sock->local_addr;
            const uint32_t bit = 1U << (group - 1);
            if (option_name == NETLINK_ADD_MEMBERSHIP) {
                nl_socket->nl_groups |= bit;
            } else {
                nl_socket->nl_groups &= ~bit;
            }
            return 0;
        }
        default:
            break;
        }
    }
    setsockopt_print_unsupported_error(level, option_name);
    errno = ENOPROTOOPT;
    return -1;
}

void getsockopt_print_unsupported_error(const int level, const int option_name) {
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
            nfl_log("getsockopt | level: SOL_SOCKET | option: %d "
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
            nfl_log("getsockopt | level: SOL_NETLINK | option: %d "
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
            nfl_log("getsockopt | level: IPPROTO_IP | option: %d "
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
            nfl_log("getsockopt | level: IPPROTO_IPV6 | option: %d "
                         "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                         option_name);
        }
    } else {
        nfl_log("getsockopt | level: %d | option: %d "
                     "not relevant or unsupported by model. Returning error EOPNOTSUPP.",
                     level, option_name);
    }
}

void setsockopt_print_unsupported_error(const int level, const int option_name) {
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
            nfl_log("setsockopt | level: SOL_SOCKET | option: %d "
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
            nfl_log("setsockopt | level: SOL_NETLINK | option: %d "
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
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_TRANSPARENT);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_TTL);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, IP_UNBLOCK_SOURCE);
            WARN_CASE_SETSOCKOPT(IPPROTO_IP, SO_PEERSEC);
        default:
            nfl_log("setsockopt | level: IPPROTO_IP | option: %d "
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
            nfl_log("setsockopt | level: IPPROTO_IPV6 | option: %d "
                         "| not relevant or unsupported by model. Silent ignoring.",
                         option_name);
        }
    } else {
        nfl_log("setsockopt | level: %d | option: %d "
                     "| not relevant or unsupported by model. Silent ignoring.",
                     level, option_name);
    }
}
