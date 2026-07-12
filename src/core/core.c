#include "fd_table.h"
#include "interfaces.h"
#include "network_env.h"
#include "routing.h"
#include "core.h"
#include "handlers.h"
#include "dgram.h"
#include "rtnetlink.h"
#include "stream.h"
#include "recv_buffer.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "callback_wrapper.h"
#include "interceptors/native.h"
#include "addr.h"

int socket_nfl(const int domain, const int type, const int protocol) {
    const int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);

    const int fd = alloc_nfl_sock();
    if (fd < 0) {
        return -1;
    }
    nfl_sock_full_t *sock = get_nfl_sock(fd);
    if (!sock) {
        return -1;
    }

    sock->domain = domain;
    sock->type = base_type;
    sock->protocol = protocol;
    sock->status_flags.blocking = !(type & SOCK_NONBLOCK);
    // shutdown_read, shutdown_write, is_listening are zero from calloc().

    if (sock->domain == AF_INET || sock->domain == AF_INET6) {
        if (sock->protocol == 0) { // Set default protocol for sock type if protocol wasn't given
            if (sock->type == SOCK_STREAM) {
                sock->protocol = IPPROTO_TCP;
            }
            if (sock->type == SOCK_DGRAM) {
                sock->protocol = IPPROTO_UDP;
            }
        }
    }
    if (sock->domain == AF_NETLINK) {
        sock->remote_addr = calloc(1, sizeof(nfl_addr_t));
        if (!sock->remote_addr) {
            errno = ENOMEM;
            return -1;
        }
        sock->remote_addr->nl.nl_family = AF_NETLINK;
        sock->remote_addr->nl.nl_groups = 0;
        sock->remote_addr->nl.nl_pid = 0; // kernel
    }
    nfl_log("socket() success, new %s", sock_to_str(sock));
    return fd;
}

int bind_nfl(nfl_sock_full_t *sock, const nfl_addr_t *addr, const socklen_t len) {
    if (!addr || !len) {
        errno = EINVAL;
        return -1;
    }

    if (sock->local_addr) { // Already bound
        errno = EINVAL;
        return -1;
    }

    // NOLINTNEXTLINE(clang-analyzer-core.UndefinedBinaryOperatorResult)
    if (addr->s.sa_family != sock->domain) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    const socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);
    if (len < correct_addrlen) {
        errno = EINVAL;
        return -1;
    }
    if (!can_bind_to_address(sock, addr)) {
        errno = EADDRNOTAVAIL;
        return -1;
    }

    nfl_addr_t *local_addr = malloc(sizeof(nfl_addr_t));
    if (!local_addr) {
        errno = ENOMEM;
        return -1;
    }
    // Caller may pass a larger addrlen (e.g. sockaddr_storage), only family-specific bytes matter.
    memcpy(local_addr, addr, correct_addrlen);
    // Linux: bind(port=0) auto-assigns an ephemeral port.
    if (sock->domain == AF_INET && local_addr->s4.sin_port == 0) {
        local_addr->s4.sin_port = get_ephemeral_local_port_network_byte_order();
    } else if (sock->domain == AF_INET6 && local_addr->s6.sin6_port == 0) {
        local_addr->s6.sin6_port = get_ephemeral_local_port_network_byte_order();
    }
    /* Netlink: when caller passes nl_pid=0, kernel auto-assigns a unique port id.
     * Use a process-local counter. A zero port id would alias "kernel" in responses. */
    else if (sock->domain == AF_NETLINK && local_addr->nl.nl_pid == 0) {
        static uint32_t next_nl_pid = 1;
        local_addr->nl.nl_pid = next_nl_pid++;
    }
    sock->local_addr = local_addr;
    nfl_log("bind() success: %s", sock_to_str(sock));
    nfl_sock_bind_priv((const nfl_sock_t *)sock);
    return 0;
}

uint16_t get_ephemeral_local_port_network_byte_order() {
    static uint16_t next_available_ephemeral_port = 10000;
    return htons(next_available_ephemeral_port++);
}

int autobind_udp(nfl_sock_full_t *sock, const nfl_addr_t *remote_addr) {
    assert(!sock->local_addr);

    nfl_l3_iface_t *local_network_device_address = routing_table_lookup(remote_addr);
    if (!local_network_device_address) {
        errno = ENETUNREACH;
        return -1;
    }
    const uint16_t ephemeral_port = get_ephemeral_local_port_network_byte_order();
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
    }
    if (sock->domain == AF_INET6) {
        struct sockaddr_in6 bound_addr_ipv6 = {};
        bound_addr_ipv6.sin6_family = AF_INET6;
        memcpy(&bound_addr_ipv6.sin6_addr, &local_network_device_address->addr->s6.sin6_addr, sizeof(struct in6_addr));
        bound_addr_ipv6.sin6_port = ephemeral_port;
        return bind_nfl(sock, (const nfl_addr_t *)&bound_addr_ipv6, get_socket_domain_addrlen(sock->domain));
    }
    nfl_die(1, "autobind_udp called on sock with unsupported domain");
}

int connect_nfl(nfl_sock_full_t *sock, const nfl_addr_t *addr, const socklen_t addrlen) {
    if (addr && (addr->s.sa_family != AF_UNSPEC && addr->s.sa_family != sock->domain)) {
        errno = EAFNOSUPPORT;
        return -1;
    }

    if (sock->domain == AF_NETLINK) {
        // Netlink connect() sets the default destination. AF_UNSPEC clears it.
        if (!addr || addr->s.sa_family == AF_UNSPEC) {
            if (sock->remote_addr) {
                free(sock->remote_addr);
                sock->remote_addr = NULL;
            }
            return 0;
        }
        if (addrlen < (socklen_t)sizeof(struct sockaddr_nl)) {
            errno = EINVAL;
            return -1;
        }
        nfl_addr_t *new_remote = malloc(sizeof(nfl_addr_t));
        if (!new_remote) {
            errno = ENOMEM;
            return -1;
        }
        memcpy(new_remote, addr, sizeof(struct sockaddr_nl));
        if (sock->remote_addr) {
            free(sock->remote_addr);
        }
        sock->remote_addr = new_remote;
        return 0;
    }

    /* For SOCK_DGRAM (incl. ICMP datagram) and SOCK_RAW, connect() sets the default
     * destination, the dgram path implements that semantic correctly. */
    if (sock->type == SOCK_DGRAM || sock->type == SOCK_RAW) {
        return connect_dgram(sock, addr, addrlen);
    }
    if (sock->type == SOCK_STREAM) {
        return connect_stream(sock, addr, addrlen);
    }
    nfl_die(1, "Connect on sock with unsupported protocol, code should not be reachable");
}

static int getsockpeername_helper(const nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *addrlen, const bool get_local_addr) {
    if (!addrlen || *addrlen < 0) {
        errno = EINVAL;
        return -1;
    }
    nfl_addr_t *requested_address = get_local_addr ? sock->local_addr : sock->remote_addr;

    if (!requested_address) {
        errno = get_local_addr ? EINVAL : ENOTCONN;
        return -1;
    }
    const socklen_t correct_addrlen = get_socket_domain_addrlen(sock->domain);
    const socklen_t bytes_to_copy = *addrlen < correct_addrlen ? *addrlen : correct_addrlen;
    memcpy(addr, requested_address, bytes_to_copy);
    *addrlen = correct_addrlen;
    return 0;
}

int getpeername_nfl(const nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *addrlen) {
    return getsockpeername_helper(sock, addr, addrlen, false);
}

int getsockname_nfl(const nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *addrlen) {
    return getsockpeername_helper(sock, addr, addrlen, true);
}

int shutdown_nfl(nfl_sock_full_t *sock, const int how) {
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
    sock_readiness_changed(sock); // shutdown surfaces EPOLLRDHUP / EPOLLHUP
    nfl_log("shutdown() success: %s", sock_to_str(sock));
    return 0;
}

ssize_t read_nfl(nfl_sock_full_t *sock, void *buf, const size_t count) {
    return recvfrom_nfl(sock, buf, count, 0, NULL, NULL);
}

ssize_t recvfrom_nfl(nfl_sock_full_t *sock, void *buf, const size_t len, const int flags, nfl_addr_t *remote_addr, socklen_t *addrlen) {
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

    const ssize_t s = recvmsg_nfl(sock, &msg, flags);

    if (addrlen) {
        *addrlen = msg.msg_namelen;
    }
    return s;
}

static nfl_recv_flags recv_flags_decode(const int flags) {
    return (nfl_recv_flags){
        .msg_dontwait = (flags & MSG_DONTWAIT) != 0,
        .msg_peek = (flags & MSG_PEEK) != 0,
        .msg_trunc = (flags & MSG_TRUNC) != 0,
    };
}

ssize_t recvmsg_nfl(nfl_sock_full_t *sock, struct msghdr *msg, const int flags) {
    if (sock->shutdown_read) {
        // recv after shutdown(SHUT_RD) is end-of-stream: return 0 with no errno.
        return 0;
    }

    if (!msg) {
        errno = EFAULT;
        return -1;
    }
    if (flags & MSG_OOB) {
        nfl_log("recv with MSG_OOB flag, not modelled");
    }
    if (flags & MSG_ERRQUEUE) {
        nfl_log("recv with MSG_ERRQUEUE flag, not modelled");
    }

    msg->msg_flags = 0;

    const nfl_recv_flags rf = recv_flags_decode(flags);
    if (sock->domain == AF_NETLINK) {
        return recvmsg_netlink(sock, msg, rf);
    }
    if (sock->type == SOCK_DGRAM || sock->type == SOCK_RAW) {
        return recvmsg_dgram(sock, msg, rf);
    }
    if (sock->type == SOCK_STREAM) {
        return recvmsg_stream(sock, msg, rf);
    }
    __builtin_unreachable();
}

int recvmmsg_nfl(nfl_sock_full_t *sock, struct mmsghdr *msgvec, const unsigned int vlen, const int flags, const struct timespec *timeout) {
    (void)timeout;
    if (!msgvec) {
        errno = EFAULT;
        return -1;
    }
    unsigned int n = 0;
    for (; n < vlen; n++) {
        const ssize_t r = recvmsg_nfl(sock, &msgvec[n].msg_hdr, flags);
        if (r < 0) {
            return n > 0 ? (int)n : -1;
        }
        msgvec[n].msg_len = (unsigned int)r;
        if (r == 0 && n > 0) {
            return (int)n + 1;
        }
        if ((flags & MSG_DONTWAIT) && r == 0) {
            break;
        }
    }
    return (int)n;
}

ssize_t readv_nfl(nfl_sock_full_t *sock, const struct iovec *iov, const int iovcnt) {
    if (iovcnt < 0 || (iovcnt > 0 && !iov)) {
        errno = EINVAL;
        return -1;
    }
    struct msghdr msg = { 0 };
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = (size_t)iovcnt;
    return recvmsg_nfl(sock, &msg, 0);
}

ssize_t write_nfl(nfl_sock_full_t *sock, void const *buf, const size_t len) {
    return sendto_nfl(sock, buf, len, 0, NULL, 0);
}

ssize_t sendto_nfl(nfl_sock_full_t *sock, const void *buf, const size_t len, const int flags, const nfl_addr_t *remote_addr, const socklen_t addrlen) {
    struct iovec iov;
    struct msghdr msg;

    if (!remote_addr && addrlen) {
        nfl_log("Sendto called with invalid remote_addr or addrlen");
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

ssize_t sendmsg_nfl(nfl_sock_full_t *sock, const struct msghdr *msg, const int flags) {
    if (sock->shutdown_write) {
        errno = EPIPE;
        nfl_log("Send/to/msg called on non writable sock");
        return -1;
    }

    if (!sock->remote_addr && !(msg->msg_name && msg->msg_namelen)) {
        // No destination: TCP without connect() -> ENOTCONN, UDP without sendto-addr -> EDESTADDRREQ.
        errno = (sock->type == SOCK_STREAM) ? ENOTCONN : EDESTADDRREQ;
        return -1;
    }

    if (sock->domain == AF_NETLINK) {
        return sendmsg_netlink(sock, msg);
    }
    if (sock->type == SOCK_DGRAM || sock->type == SOCK_RAW) {
        return sendmsg_dgram(sock, msg);
    }
    if (sock->type == SOCK_STREAM) {
        return sendmsg_stream(sock, msg, flags);
    }
    __builtin_unreachable();
}

ssize_t writev_nfl(nfl_sock_full_t *sock, const struct iovec *iov, const int iovcnt) {
    if (iovcnt < 0 || (iovcnt > 0 && !iov)) {
        errno = EINVAL;
        return -1;
    }
    struct msghdr msg = { 0 };
    msg.msg_iov = (struct iovec *)iov;
    msg.msg_iovlen = (size_t)iovcnt;
    return sendmsg_nfl(sock, &msg, 0);
}

int sendmmsg_nfl(nfl_sock_full_t *sock, struct mmsghdr *msgvec, const unsigned int vlen, const int flags) {
    if (!msgvec) {
        errno = EFAULT;
        return -1;
    }
    unsigned int n = 0;
    for (; n < vlen; n++) {
        const ssize_t r = sendmsg_nfl(sock, &msgvec[n].msg_hdr, flags);
        if (r < 0) {
            return n > 0 ? (int)n : -1;
        }
        msgvec[n].msg_len = (unsigned int)r;
    }
    return (int)n;
}

/* sendfile(2) into an nfl socket. The kernel form does zero-copy file→socket,
 * but we have no kernel socket to splice into, so we read up to one chunk
 * from the (native) input fd and pump it through write_nfl. Caps at 64 KiB
 * per call to avoid huge intermediate allocations, matching Linux's documented
 * behaviour of returning fewer bytes than requested. */
ssize_t sendfile_nfl(nfl_sock_full_t *sock, int in_fd, off_t *offset, size_t count) {
    if (count == 0) {
        return 0;
    }
    /* in_fd must be a real file (or anything readable in the kernel). An nfl
     * fd here makes no sense, there's nothing for the kernel to read from. */
    if (get_nfl_sock(in_fd) != NULL) {
        errno = EINVAL;
        return -1;
    }
    const size_t chunk = count > (1U << 16) ? (1U << 16) : count;
    char *buf = malloc(chunk);
    if (!buf) {
        errno = ENOMEM;
        return -1;
    }
    ssize_t r;
    if (offset) {
        r = pread_native(in_fd, buf, chunk, *offset);
    } else {
        r = read_native(in_fd, buf, chunk);
    }
    if (r < 0) {
        const int saved = errno;
        free(buf);
        errno = saved;
        return -1;
    }
    if (r == 0) {
        free(buf);
        return 0;
    }
    const ssize_t sent = write_nfl(sock, buf, (size_t)r);
    const int saved = errno;
    free(buf);
    if (sent < 0) {
        errno = saved;
        return -1;
    }
    if (offset) {
        *offset += sent;
    }
    return sent;
}
