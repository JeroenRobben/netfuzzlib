/* Testing-only nfl module that plumbs nfl_send/recv/accept/connect to real
 * kernel sockets, so an unmodified external client (curl, ssh, dig, …) can
 * drive a daemon-under-test that's running under libnfl. Trades the
 * model's determinism for end-to-end protocol exchanges, not for fuzzing. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netfuzzlib/api.h>
#include <netfuzzlib/callbacks.h>

/* *_native wrappers bypass our own libc interceptors. */
#include "interceptors/native.h"
#include "core/handlers.h"
#include "core/interfaces.h"
#include "core/recv_buffer.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

enum {
    BRIDGE_RECV_BUF_LEN = 65536,
    BRIDGE_MAX_SOCKS = 256,
    BRIDGE_MAX_LISTENERS = 16,
    BRIDGE_LISTEN_BACKLOG = 8,
    BRIDGE_IDLE_WAIT_MS = 50,
    /* How long a blocking recv waits for real data before giving the framework
     * back an empty read (which it turns into EINTR). Long enough for a real
     * peer to send its next request, bounded so the run never wedges. */
    BRIDGE_BLOCKING_RECV_WAIT_MS = 2000,
    BRIDGE_FD_BASE = NFL_RESERVED_FD_MODULE_START,
};

static int bridge_relocate_fd(int fd) {
    if (fd < 0 || fd >= BRIDGE_FD_BASE) {
        return fd;
    }
    const int hi = fcntl_native(fd, F_DUPFD_CLOEXEC, BRIDGE_FD_BASE);
    if (hi < 0) {
        return fd;
    }
    close_native(fd);
    return hi;
}


static void format_addr(const nfl_addr_t *a, char *buf, size_t blen) {
    if (!a) {
        snprintf(buf, blen, "<null>");
        return;
    }
    char host[INET6_ADDRSTRLEN] = {0};
    if (a->s.sa_family == AF_INET) {
        inet_ntop(AF_INET, &a->s4.sin_addr, host, sizeof(host));
        snprintf(buf, blen, "%s:%u", host, ntohs(a->s4.sin_port));
    } else if (a->s.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &a->s6.sin6_addr, host, sizeof(host));
        snprintf(buf, blen, "[%s]:%u", host, ntohs(a->s6.sin6_port));
    } else {
        snprintf(buf, blen, "<af=%d>", a->s.sa_family);
    }
}

/* Recover the full nfl_sock_full_t (we're in the same address space). */
static const nfl_sock_full_t *as_full_sock(const nfl_sock_t *m) {
    return (const nfl_sock_full_t *)m;
}

/* ---------- Per-socket state ---------- */

typedef struct {
    const void *key;     /* nfl_sock_t pointer, stable per nfl socket */
    int real_fd;         /* real kernel fd backing this nfl socket */
    int domain;
    int type;
    bool is_listener;    /* true means real_fd is a listening kernel socket */
} bridge_sock_t;

static bridge_sock_t bridge_socks[BRIDGE_MAX_SOCKS];
static size_t bridge_socks_n = 0;

static bridge_sock_t *bridge_find(const void *key) {
    for (size_t i = 0; i < bridge_socks_n; i++) {
        if (bridge_socks[i].key == key) {
            return &bridge_socks[i];
        }
    }
    return NULL;
}

static bridge_sock_t *bridge_insert(const void *key, int real_fd, int domain, int type, bool is_listener) {
    if (bridge_socks_n >= BRIDGE_MAX_SOCKS) {
        nfl_log("bridge_insert: too many sockets (max %d)", BRIDGE_MAX_SOCKS);
        return NULL;
    }
    bridge_sock_t *s = &bridge_socks[bridge_socks_n++];
    s->key = key;
    s->real_fd = real_fd;
    s->domain = domain;
    s->type = type;
    s->is_listener = is_listener;
    return s;
}

/* ---------- Real-listener cache (one per listener local_addr) ---------- */

typedef struct {
    nfl_addr_t local_addr; /* listener's bound address, network byte order */
    int domain;
    int real_fd;           /* SOCK_STREAM, listening, SO_REUSEADDR set */
} bridge_listener_t;

static bridge_listener_t bridge_listeners[BRIDGE_MAX_LISTENERS];
static size_t bridge_listeners_n = 0;

static bool addr_equal(const nfl_addr_t *a, const nfl_addr_t *b) {
    if (a->s.sa_family != b->s.sa_family) return false;
    if (a->s.sa_family == AF_INET) {
        return a->s4.sin_port == b->s4.sin_port
            && a->s4.sin_addr.s_addr == b->s4.sin_addr.s_addr;
    }
    if (a->s.sa_family == AF_INET6) {
        return a->s6.sin6_port == b->s6.sin6_port
            && memcmp(&a->s6.sin6_addr, &b->s6.sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return false;
}

static int open_real_listener(const nfl_addr_t *local_addr, bool v6only) {
    int fd = socket_native(local_addr->s.sa_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        nfl_log("open_real_listener: socket() failed: %s", strerror(errno));
        return -1;
    }
    fd = bridge_relocate_fd(fd);
    int one = 1;
    if (setsockopt_native(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
        nfl_log("open_real_listener: SO_REUSEADDR failed: %s", strerror(errno));
    }
    if (local_addr->s.sa_family == AF_INET6 && v6only) {
        setsockopt_native(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }
    socklen_t alen = (local_addr->s.sa_family == AF_INET)
                         ? sizeof(struct sockaddr_in)
                         : sizeof(struct sockaddr_in6);
    if (bind_native(fd, &local_addr->s, alen) < 0) {
        char buf[64];
        format_addr(local_addr, buf, sizeof(buf));
        nfl_log("open_real_listener: bind(%s) failed: %s", buf, strerror(errno));
        close_native(fd);
        return -1;
    }
    if (listen_native(fd, BRIDGE_LISTEN_BACKLOG) < 0) {
        nfl_log("open_real_listener: listen() failed: %s", strerror(errno));
        close_native(fd);
        return -1;
    }
    char buf[64];
    format_addr(local_addr, buf, sizeof(buf));
    nfl_log("listener ready on %s (real fd=%d)", buf, fd);
    return fd;
}

static int get_or_create_listener(const nfl_addr_t *local_addr, bool v6only) {
    for (size_t i = 0; i < bridge_listeners_n; i++) {
        if (addr_equal(&bridge_listeners[i].local_addr, local_addr)) {
            return bridge_listeners[i].real_fd;
        }
    }
    if (bridge_listeners_n >= BRIDGE_MAX_LISTENERS) {
        nfl_log("get_or_create_listener: too many listeners (max %d)", BRIDGE_MAX_LISTENERS);
        return -1;
    }
    const int fd = open_real_listener(local_addr, v6only);
    if (fd < 0) {
        return -1;
    }
    bridge_listener_t *l = &bridge_listeners[bridge_listeners_n++];
    memcpy(&l->local_addr, local_addr, sizeof(*local_addr));
    l->domain = local_addr->s.sa_family;
    l->real_fd = fd;
    return fd;
}


static socklen_t sockaddr_len_for(sa_family_t fam) {
    return (fam == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
}

static void fill_nfl_from_sockaddr(nfl_addr_t *dst, const struct sockaddr_storage *src) {
    if (src->ss_family == AF_INET) {
        memcpy(&dst->s4, src, sizeof(struct sockaddr_in));
    } else if (src->ss_family == AF_INET6) {
        memcpy(&dst->s6, src, sizeof(struct sockaddr_in6));
    }
}

static int open_real_udp(int domain, const nfl_addr_t *local_addr, bool v6only) {
    int fd = socket_native(domain, SOCK_DGRAM, 0);
    if (fd < 0) {
        nfl_log("open_real_udp: socket() failed: %s", strerror(errno));
        return -1;
    }
    fd = bridge_relocate_fd(fd);
    int one = 1;
    setsockopt_native(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (domain == AF_INET6 && v6only) {
        setsockopt_native(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    }
    if (domain == AF_INET) {
        setsockopt_native(fd, IPPROTO_IP, IP_PKTINFO, &one, sizeof(one));
    } else if (domain == AF_INET6) {
        setsockopt_native(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &one, sizeof(one));
    }
    if (local_addr) {
        if (bind_native(fd, &local_addr->s, sockaddr_len_for(local_addr->s.sa_family)) < 0) {
            char buf[64];
            format_addr(local_addr, buf, sizeof(buf));
            nfl_log("open_real_udp: bind(%s) failed: %s", buf, strerror(errno));
            close_native(fd);
            return -1;
        }
        char buf[64];
        format_addr(local_addr, buf, sizeof(buf));
        nfl_log("UDP socket bound to %s (real fd=%d)", buf, fd);
    }
    return fd;
}


int nfl_setup() {
    nfl_log("module-bridge-kernel initialised");
    return 0;
}

void nfl_sock_bind(const nfl_sock_t *sock) {
    const nfl_addr_t *local_addr = sock->local_addr;
    if (!local_addr || sock->type != SOCK_DGRAM) {
        return;
    }
    if (bridge_find(sock)) {
        return;
    }
    const int fd = open_real_udp(sock->domain, local_addr, as_full_sock(sock)->status_flags.v6only);
    if (fd < 0) {
        char buf[64];
        format_addr(local_addr, buf, sizeof(buf));
        nfl_log("nfl_sock_bind: failed to open kernel UDP socket for %s", buf);
        return;
    }
    if (!bridge_insert(sock, fd, sock->domain, sock->type, false)) {
        close_native(fd);
    }
}

void nfl_sock_listen(const nfl_sock_t *sock) {
    const nfl_addr_t *local_addr = sock->local_addr;
    if (!local_addr) return;
    if (get_or_create_listener(local_addr, as_full_sock(sock)->status_flags.v6only) < 0) {
        char buf[64];
        format_addr(local_addr, buf, sizeof(buf));
        nfl_log("nfl_sock_listen: failed to open kernel listener for %s", buf);
    }
}

bool nfl_tcp_connect(const nfl_sock_t *sock, const nfl_addr_t *remote_addr) {
    char rbuf[64];
    format_addr(remote_addr, rbuf, sizeof(rbuf));

    int fd = socket_native(remote_addr->s.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        nfl_log("tcp_connect socket() failed: %s", strerror(errno));
        return false;
    }
    fd = bridge_relocate_fd(fd);
    if (connect_native(fd, &remote_addr->s, sockaddr_len_for(remote_addr->s.sa_family)) < 0) {
        nfl_log("tcp_connect %s failed: %s", rbuf, strerror(errno));
        close_native(fd);
        return false;
    }
    if (!bridge_insert(sock, fd, sock->domain, sock->type, false)) {
        close_native(fd);
        return false;
    }
    nfl_log("tcp_connect %s ok (real fd=%d)", rbuf, fd);
    return true;
}

bool nfl_tcp_accept(const nfl_sock_t *sock, nfl_addr_t *remote_addr) {
    const nfl_addr_t *local_addr = sock->local_addr;
    if (!local_addr) return false;
    char lbuf[64];
    format_addr(local_addr, lbuf, sizeof(lbuf));

    const int listen_fd = get_or_create_listener(local_addr, as_full_sock(sock)->status_flags.v6only);
    if (listen_fd < 0) {
        nfl_log("tcp_accept(%s): no real listener", lbuf);
        return false;
    }

    /* Always non-blocking: if no client is waiting we return false and the
     * framework spins, nfl_socket_idle does the waiting. */
    struct sockaddr_storage peer = {0};
    socklen_t plen = sizeof(peer);
    int child_fd = accept_native(listen_fd, (struct sockaddr *)&peer, &plen);
    if (child_fd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        nfl_log("tcp_accept(%s): accept failed: %s", lbuf, strerror(errno));
        return false;
    }
    child_fd = bridge_relocate_fd(child_fd);

    fill_nfl_from_sockaddr(remote_addr, &peer);
    if (!bridge_insert(sock, child_fd, sock->domain, sock->type, false)) {
        close_native(child_fd);
        return false;
    }
    char rbuf[64];
    format_addr(remote_addr, rbuf, sizeof(rbuf));
    nfl_log("tcp_accept(%s): peer %s connected (real fd=%d)", lbuf, rbuf, child_fd);
    return true;
}

nfl_conn_result nfl_send(const nfl_sock_t *sock, const nfl_addr_t *to,
                         const struct iovec *iov, size_t iovlen) {
    bridge_sock_t *bs = bridge_find(sock);

    /* Lazy-create on first send for a SUT that bound but hasn't received yet. */
    if (!bs && sock->type == SOCK_DGRAM) {
        const int fd = open_real_udp(sock->domain, sock->local_addr, as_full_sock(sock)->status_flags.v6only);
        if (fd < 0) return NFL_CONN_CLOSED;
        bs = bridge_insert(sock, fd, sock->domain, sock->type, false);
        if (!bs) { close_native(fd); return NFL_CONN_CLOSED; }
    }

    if (!bs) {
        nfl_log("nfl_send: no real fd for sock %p (type=%d)", (const void *)sock, sock->type);
        return NFL_CONN_CLOSED;
    }

    struct msghdr m = {0};
    if (bs->type != SOCK_STREAM && to) {
        m.msg_name = (void *)&to->s;
        m.msg_namelen = sockaddr_len_for(to->s.sa_family);
    }
    m.msg_iov = (struct iovec *)iov;
    m.msg_iovlen = iovlen;
    /* MSG_NOSIGNAL: a write to a dead peer must not raise SIGPIPE and kill the
     * SUT process. Report it as a closed connection so the framework maps it to
     * the right send(2) errno. */
    const ssize_t n = sendmsg_native(bs->real_fd, &m, MSG_NOSIGNAL);
    if (n < 0) {
        nfl_log("sendmsg real fd=%d failed: %s", bs->real_fd, strerror(errno));
        if (errno == EPIPE || errno == ECONNRESET || errno == ECONNREFUSED || errno == ENOTCONN) {
            return NFL_CONN_CLOSED;
        }
        return NFL_CONN_OK;
    }
    char tbuf[64];
    format_addr(to, tbuf, sizeof(tbuf));
    nfl_log("sendmsg real fd=%d → %s %zd bytes", bs->real_fd, tbuf, n);
    return NFL_CONN_OK;
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    *pkt = NULL;
    bridge_sock_t *bs = bridge_find(sock);

    if (!bs && sock->type == SOCK_DGRAM) {
        const int fd = open_real_udp(sock->domain, sock->local_addr, as_full_sock(sock)->status_flags.v6only);
        if (fd < 0) return NFL_CONN_OK;
        bs = bridge_insert(sock, fd, sock->domain, sock->type, false);
        if (!bs) { close_native(fd); return NFL_CONN_OK; }
    }
    if (!bs) {
        nfl_log("nfl_receive: no real fd for sock %p (type=%d)", (const void *)sock, sock->type);
        return NFL_CONN_OK;
    }

    /* The framework never blocks: a blocking recv with no data waiting just gets
     * EINTR. So a real peer that hasn't sent its next request yet would look like
     * a dead connection to the SUT. For a blocking socket, wait here (bounded) for
     * the real fd to become readable, so the data is in hand when the framework
     * checks. A non-blocking socket keeps the poll-free path and gets EAGAIN at
     * once, as the SUT asked. This is safe because poll/select readiness checks
     * never route through nfl_receive for a connected socket. */
    if (as_full_sock(sock)->status_flags.blocking) {
        struct pollfd pfd = { .fd = bs->real_fd, .events = POLLIN, .revents = 0 };
        if (poll_native(&pfd, 1, BRIDGE_BLOCKING_RECV_WAIT_MS) == 0) {
            return NFL_CONN_OK; // nothing arrived in time, let the framework report EINTR
        }
    }

    /* Receive into a scratch buffer first: we don't know the length up front, and
     * on a dry socket there is nothing to deliver. Only once we have data do we
     * allocate the packet the framework will own and free. */
    char scratch[BRIDGE_RECV_BUF_LEN];

    if (bs->type == SOCK_STREAM) {
        const ssize_t n = recvfrom_native(bs->real_fd, scratch, sizeof(scratch), MSG_DONTWAIT, NULL, NULL);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            return NFL_CONN_OK;
        }
        if (n < 0) {
            nfl_log("recv real fd=%d failed: %s", bs->real_fd, strerror(errno));
            return NFL_CONN_OK;
        }
        if (n == 0) {
            nfl_log("recv real fd=%d: peer EOF", bs->real_fd);
            return NFL_CONN_CLOSED;
        }
        nfl_pkt *p = nfl_alloc_pkt((size_t)n);
        if (!p) {
            nfl_log("nfl_receive: nfl_alloc_pkt failed");
            return NFL_CONN_OK;
        }
        memcpy(p->buf, scratch, (size_t)n);
        *pkt = p;
        nfl_log("recv real fd=%d: %zd bytes (TCP)", bs->real_fd, n);
        return NFL_CONN_OK;
    }

    struct sockaddr_storage peer = {0};
    struct iovec recv_iov = { .iov_base = scratch, .iov_len = sizeof(scratch) };
    char cbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];  // big enough for v4 too
    struct msghdr rmsg = {
        .msg_name = &peer,
        .msg_namelen = sizeof(peer),
        .msg_iov = &recv_iov,
        .msg_iovlen = 1,
        .msg_control = cbuf,
        .msg_controllen = sizeof(cbuf),
    };
    const ssize_t n = recvmsg_native(bs->real_fd, &rmsg, MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return NFL_CONN_OK;
    }
    if (n < 0) {
        nfl_log("recvmsg real fd=%d failed: %s", bs->real_fd, strerror(errno));
        return NFL_CONN_OK;
    }
    nfl_pkt *p = nfl_alloc_pkt((size_t)n);
    if (!p) {
        nfl_log("nfl_receive: nfl_alloc_pkt failed");
        return NFL_CONN_OK;
    }
    memcpy(p->buf, scratch, (size_t)n);
    *pkt = p;
    fill_nfl_from_sockaddr(&info->src_addr, &peer);
    if (sock->local_addr) {
        memcpy(&info->dst_addr, sock->local_addr, sizeof(*sock->local_addr));
    }
    unsigned int ifindex_from_cmsg = 1;  // lo fallback
    for (struct cmsghdr *c = CMSG_FIRSTHDR(&rmsg); c; c = CMSG_NXTHDR(&rmsg, c)) {
        if (c->cmsg_level == IPPROTO_IP && c->cmsg_type == IP_PKTINFO &&
            c->cmsg_len >= CMSG_LEN(sizeof(struct in_pktinfo))) {
            const struct in_pktinfo *pi = (const struct in_pktinfo *)CMSG_DATA(c);
            if (info->dst_addr.s.sa_family == AF_INET) {
                info->dst_addr.s4.sin_addr = pi->ipi_addr;
            }
            ifindex_from_cmsg = (unsigned)pi->ipi_ifindex;
        } else if (c->cmsg_level == IPPROTO_IPV6 && c->cmsg_type == IPV6_PKTINFO &&
                   c->cmsg_len >= CMSG_LEN(sizeof(struct in6_pktinfo))) {
            const struct in6_pktinfo *pi6 = (const struct in6_pktinfo *)CMSG_DATA(c);
            if (info->dst_addr.s.sa_family == AF_INET6) {
                info->dst_addr.s6.sin6_addr = pi6->ipi6_addr;
            }
            ifindex_from_cmsg = pi6->ipi6_ifindex;
        }
    }
    info->iface_index = ifindex_from_cmsg;
    nfl_log("recvmsg real fd=%d: %zd bytes (UDP)", bs->real_fd, n);
    return NFL_CONN_OK;
}

void nfl_sock_close(const nfl_sock_t *sock) {
    for (size_t i = 0; i < bridge_socks_n; i++) {
        if (bridge_socks[i].key != sock) continue;
        nfl_log("nfl_sock_close: closing real fd=%d for sock=%p",
                bridge_socks[i].real_fd, (const void *)sock);
        if (bridge_socks[i].real_fd >= 0) close_native(bridge_socks[i].real_fd);
        bridge_socks[i] = bridge_socks[bridge_socks_n - 1];
        bridge_socks_n--;
        return;
    }
}

void nfl_socket_idle(const nfl_sock_t *sock) {
    (void)sock;
    struct pollfd pfds[BRIDGE_MAX_SOCKS + BRIDGE_MAX_LISTENERS];
    nfds_t n = 0;
    for (size_t i = 0; i < bridge_socks_n; i++) {
        if (bridge_socks[i].real_fd >= 0) {
            pfds[n].fd = bridge_socks[i].real_fd;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++;
        }
    }
    for (size_t i = 0; i < bridge_listeners_n; i++) {
        if (bridge_listeners[i].real_fd >= 0) {
            pfds[n].fd = bridge_listeners[i].real_fd;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            n++;
        }
    }
    if (n > 0) {
        poll_native(pfds, n, BRIDGE_IDLE_WAIT_MS);
    }
    /* Always spin: the bridge waits on real fds and never ends the run itself. */
}
