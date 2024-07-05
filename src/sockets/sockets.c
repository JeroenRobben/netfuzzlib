#include "hooks/hooks.h"
#include "environment/network_env.h"
#include "environment/routing.h"
#include "sockets.h"
#include "sockets_dgram.h"
#include "sockets_rtnetlink.h"
#include "sockets_stream.h"
#include "sockets_util.h"
#include "environment/fd_table.h"
#include "environment/interfaces.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

int socket_nfl(int domain, int type, int protocol) {
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

    int fd = alloc_nfl_sock();
    if (fd < 0)
        return -1;
    nfl_sock_t *sock = get_nfl_sock(fd);
    if (!sock) {
        return -1;
    }

    sock->domain = domain;
    sock->type = base_type;
    sock->protocol = protocol;
    sock->shutdown_write = 0;
    sock->shutdown_write = 0;
    sock->is_listening = 0;
    sock->status_flags.blocking = !IS_FLAG_SET(type, SOCK_NONBLOCK);

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        if (sock->protocol == 0) { //Set default protocol for sock type if protocol wasn't given
            if (sock->type == SOCK_STREAM)
                sock->protocol = IPPROTO_TCP;
            if (sock->type == SOCK_DGRAM)
                sock->protocol = IPPROTO_UDP;
        }
    }
    if (sock->protocol == IPPROTO_ICMP || sock->protocol == IPPROTO_ICMPV6) {
        sock->local_addr = calloc(1, sizeof(nfl_addr_t));
        if (!sock->local_addr) {
            errno = ENOBUFS;
            return -1;
        }
        sock->local_addr->s.sa_family = domain;
    }
    if (sock->domain == AF_NETLINK) {
        sock->remote_addr = calloc(1, sizeof(nfl_addr_t));
        if (!sock->remote_addr) {
            errno = ENOMEM;
            return -1;
        }
        sock->remote_addr->nl.nl_family = AF_NETLINK;
        sock->remote_addr->nl.nl_groups = 0;
        sock->remote_addr->nl.nl_pid = 0; //kernel
    }
    nfl_log_info("socket() success, new %s", sock_to_str(sock));
    return fd;
}

int bind_nfl(nfl_sock_t *sock, const nfl_addr_t *addr, socklen_t len) {
    if (!addr || !len) {
        errno = EINVAL;
        return -1;
    }

    if (sock->local_addr) { //Already bound
        errno = EINVAL;
        return -1;
    }

    if (addr->s.sa_family != sock->domain) {
        errno = EINVAL;
        return -1;
    }

    socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);
    if (len != correct_addrlen) {
        errno = EINVAL;
        return -1;
    }
    if (!can_bind_to_address(sock, addr)) {
        errno = EINVAL;
        return -1;
    }

    nfl_addr_t *local_addr = malloc(sizeof(nfl_addr_t));
    if (!local_addr) {
        errno = ENOMEM;
        return -1;
    }
    memcpy(local_addr, addr, len);
    sock->local_addr = local_addr;
    nfl_log_info("bind() success: %s", sock_to_str(sock));
    return 0;
}

uint16_t get_ephemeral_local_port_network_byte_order() {
    static uint16_t next_available_ephemeral_port = 10000;
    return htons(next_available_ephemeral_port++);
}

int autobind_udp(nfl_sock_t *sock, const nfl_addr_t *remote_addr) {
    assert(!sock->local_addr);

    nfl_l3_iface_t *local_network_device_address = routing_table_lookup(remote_addr);
    if (!local_network_device_address) {
        errno = ENETUNREACH;
        return -1;
    }
    uint16_t ephemeral_port = get_ephemeral_local_port_network_byte_order();
    if (ephemeral_port == 0) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    if (sock->domain == AF_INET) {
        struct sockaddr_in bound_addr_ipv4 = {};
        bound_addr_ipv4.sin_family = AF_INET;
        bound_addr_ipv4.sin_addr.s_addr = local_network_device_address->addr->s4.sin_addr.s_addr;
        bound_addr_ipv4.sin_port = ephemeral_port;
        return bind_nfl(sock, (const nfl_addr_t *)&bound_addr_ipv4, get_socket_domain_addrlen(sock->domain));
    } else if (sock->domain == AF_INET6) {
        struct sockaddr_in6 bound_addr_ipv6 = {};
        bound_addr_ipv6.sin6_family = AF_INET6;
        memcpy(&bound_addr_ipv6.sin6_addr, &local_network_device_address->addr->s6.sin6_addr, sizeof(struct in6_addr));
        bound_addr_ipv6.sin6_port = ephemeral_port;
        return bind_nfl(sock, (const nfl_addr_t *)&bound_addr_ipv6, get_socket_domain_addrlen(sock->domain));
    } else {
        nfl_exit_log(1, "autobind_udp called on sock with unsupported domain");
    }
}

int connect_nfl(nfl_sock_t *sock, const nfl_addr_t *addr, socklen_t addrlen) {
    if (addr && (addr->s.sa_family != AF_UNSPEC && addr->s.sa_family != sock->domain)) {
        errno = EINVAL;
        return -1;
    }

    if (sock->domain == AF_NETLINK || sock->type == SOCK_RAW || sock->protocol == IPPROTO_ICMP || sock->protocol == IPPROTO_ICMPV6) {
        nfl_log_warn("Connect called on socket which does not support this operation, %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }

    if (sock->type == SOCK_DGRAM) {
        return connect_dgram(sock, addr, addrlen);
    } else if (sock->type == SOCK_STREAM) {
        return connect_stream(sock, addr, addrlen);
    }
    nfl_exit_log(1, "Connect on sock with unsupported protocol, code should not be reachable");
}

static int getsockpeername_helper(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *addrlen, bool get_local_addr) {
    if (!addrlen || *addrlen < 0) {
        errno = EINVAL;
        return -1;
    }
    nfl_addr_t *requested_address = get_local_addr ? sock->local_addr : sock->remote_addr;

    if (!requested_address) {
        errno = EINVAL;
        return -1;
    }
    socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);
    if (*addrlen > correct_addrlen) {
        *addrlen = correct_addrlen;
    }
    memcpy(addr, requested_address, *addrlen);
    return 0;
}

int getpeername_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *addrlen) {
    return getsockpeername_helper(sock, addr, addrlen, false);
}

int getsockname_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *addrlen) {
    return getsockpeername_helper(sock, addr, addrlen, true);
}

int shutdown_nfl(nfl_sock_t *sock, int how) {
    if (sock->protocol == IPPROTO_TCP && !sock->remote_addr) {
        errno = ENOTCONN;
        return -1;
    }
    switch (how) {
    case SHUT_RD:
        sock->shutdown_read = true;
        break;
    case SHUT_WR:
        sock->shutdown_write = true;
        break;
    case SHUT_RDWR:
        sock->shutdown_read = true;
        sock->shutdown_write = true;
        break;
    default:
        errno = EINVAL;
        return -1;
    }
    nfl_log_debug("shutdown() success: %s", sock_to_str(sock));
    return 0;
}

ssize_t read_nfl(nfl_sock_t *sock, void *buf, size_t count) {
    return recvfrom_nfl(sock, buf, count, 0, NULL, 0);
}

ssize_t recvfrom_nfl(nfl_sock_t *sock, void *buf, size_t len, int flags, nfl_addr_t *remote_addr, socklen_t *addrlen) {
    if (remote_addr && !addrlen) {
        errno = EFAULT;
        return -1;
    }

    struct iovec iov;
    struct msghdr msg;

    iov.iov_base = buf;
    iov.iov_len = len;

    msg.msg_name = remote_addr;
    msg.msg_namelen = addrlen ? *addrlen : 0;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = 0;

    ssize_t s = recvmsg_nfl(sock, &msg, flags);

    if (addrlen)
        *addrlen = msg.msg_namelen;
    return s;
}

ssize_t recvmsg_nfl(nfl_sock_t *sock, struct msghdr *msg, int flags) {
    if (sock->shutdown_read) {
        errno = ESHUTDOWN;
        return 0;
    }

    if (!msg) {
        errno = EFAULT;
        return -1;
    }
    if (IS_FLAG_SET(flags, MSG_OOB)) {
        nfl_log_fatal("recv with MSG_OOB flag, not modelled");
    }
    if (IS_FLAG_SET(flags, MSG_ERRQUEUE)) {
        nfl_log_fatal("recv with MSG_ERRQUEUE flag, not modelled");
    }

    msg->msg_flags = 0;

    if (sock->domain == AF_NETLINK) {
        return recvmsg_netlink(sock, msg, flags);
    }
    if (sock->type == SOCK_DGRAM || sock->type == SOCK_RAW) {
        return recvmsg_dgram(sock, msg, flags);
    } else if (sock->type == SOCK_STREAM) {
        return recvmsg_stream(sock, msg, flags);
    }
    __builtin_unreachable();
}

int recvmmsg_nfl(nfl_sock_t *sock, void *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    nfl_log_warn("recvmmsg not supported by model");
    errno = ENOTSUP;
    return -1;
}

ssize_t write_nfl(nfl_sock_t *sock, void const *buf, size_t len) {
    return sendto_nfl(sock, buf, len, 0, NULL, 0);
}

ssize_t sendto_nfl(nfl_sock_t *sock, const void *buf, size_t len, int flags, const nfl_addr_t *remote_addr, socklen_t addrlen) {
    struct iovec iov;
    struct msghdr msg;

    if (!remote_addr && addrlen) {
        nfl_log_warn("Sendto called with invalid remote_addr or addrlen");
        errno = EFAULT;
        return -1;
    }

    iov.iov_base = (void *)buf;
    iov.iov_len = len;

    msg.msg_name = (void *)remote_addr;
    msg.msg_namelen = addrlen;
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = NULL;
    msg.msg_controllen = 0;
    msg.msg_flags = flags;
    return sendmsg_nfl(sock, &msg, flags);
}

ssize_t sendmsg_nfl(nfl_sock_t *sock, const struct msghdr *msg, int flags) {
    if (sock->shutdown_write) {
        errno = EBADF;
        nfl_log_warn("Send/to/msg called on non writable sock");
        return -1;
    }

    if (!sock->remote_addr && !(msg->msg_name && msg->msg_namelen)) {
        errno = ENOTCONN;
        return -1;
    }

    if (sock->domain == AF_NETLINK) {
        return sendmsg_netlink(sock, msg, flags);
    } else if (sock->type == SOCK_DGRAM || sock->type == SOCK_RAW) {
        return sendmsg_dgram(sock, msg, flags);
    } else if (sock->type == SOCK_STREAM) {
        return sendmsg_stream(sock, msg, flags);
    }
    __builtin_unreachable();
}
