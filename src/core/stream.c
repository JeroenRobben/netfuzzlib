#include <netfuzzlib/callbacks.h>
#include "addr.h"
#include "fd_table.h"
#include "routing.h"
#include "callback_wrapper.h"
#include "core.h"
#include "handlers.h"
#include "stream.h"
#include "recv_buffer.h"
#include <asm-generic/errno.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>

/**
 * @brief Allocate and fill in a local address for a socket that would be used for a given remote address.
 * @param remote_addr
 * @param port_network_byte_order The port to use for the local address in network byte order. If 0, an ephemeral port will be used.
 * @return
 */
static nfl_addr_t *generate_local_addr(const nfl_addr_t *remote_addr, const uint16_t port_network_byte_order) {
    nfl_l3_iface_t *local_interface = routing_table_lookup(remote_addr);
    if (!local_interface) {
        errno = ENETUNREACH;
        return NULL;
    }
    uint16_t port;

    if (port_network_byte_order == 0) {
        port = get_ephemeral_local_port_network_byte_order();
        if (port == 0) {
            errno = EADDRNOTAVAIL;
            return NULL;
        }
    } else {
        port = port_network_byte_order;
    }

    nfl_addr_t *local_addr = calloc(1, sizeof(nfl_addr_t));
    if (!local_addr) {
        errno = ENOBUFS;
        return NULL;
    }
    if (remote_addr->s.sa_family == AF_INET) {
        local_addr->s4.sin_addr.s_addr = local_interface->addr->s4.sin_addr.s_addr;
        local_addr->s4.sin_port = port;
        local_addr->s4.sin_family = AF_INET;
    } else if (remote_addr->s.sa_family == AF_INET6) {
        memcpy(&local_addr->s6.sin6_addr, &local_interface->addr->s6.sin6_addr, sizeof(struct in6_addr));
        local_addr->s6.sin6_port = port;
        local_addr->s6.sin6_family = AF_INET6;
    }
    return local_addr;
}

int connect_stream(nfl_sock_full_t *sock, const nfl_addr_t *remote_addr, const socklen_t addrlen) {
    if (!remote_addr) {
        errno = EINVAL;
        return -1;
    }

    if (sock->is_listening) { // Linux: connect on a TCP_LISTEN socket -> EISCONN.
        errno = EISCONN;
        return -1;
    }

    if (remote_addr->s.sa_family == AF_UNSPEC) {
        if (sock->remote_addr) {
            free(sock->remote_addr);
            sock->remote_addr = NULL;
        }
        if (sock->packets_ll) {
            free_packet_ll(sock->packets_ll);
            sock->packets_ll = NULL;
            sock->packet_offset = 0;
        }
        return 0;
    }

    if (sock->remote_addr) { // Already connected
        errno = EISCONN;
        return -1;
    }

    if (addrlen < get_socket_domain_addrlen(sock->domain)) {
        errno = EINVAL;
        return -1;
    }

    nfl_addr_t *prev_local_addr = sock->local_addr;
    nfl_addr_t *bound_addr = sock->local_addr;
    if (!bound_addr) {
        bound_addr = generate_local_addr(remote_addr, 0);
        if (!bound_addr) {
            return -1;
        }
    }

    nfl_addr_t *remote_addr_copy = malloc(sizeof(nfl_addr_t));
    if (!remote_addr_copy) {
        if (prev_local_addr != bound_addr) {
            free(bound_addr);
        }
        errno = ENOBUFS;
        return -1;
    }
    // Caller may pass a larger addrlen, so clamp to the family-specific size.
    memcpy(remote_addr_copy, remote_addr, get_socket_domain_addrlen(sock->domain));

    // Optimistically expose the prospective local address as sock->local_addr
    // for the callback, then roll it back if the module rejects.
    sock->local_addr = bound_addr;
    if (nfl_tcp_connect((const nfl_sock_t *)sock, remote_addr_copy)) {
        sock->remote_addr = remote_addr_copy;
        sock_readiness_changed(sock); // a connected stream socket is writable
        nfl_log("connect() success: %s", sock_to_str(sock));
        return 0;
    }
    sock->local_addr = prev_local_addr;
    if (prev_local_addr != bound_addr) {
        free(bound_addr);
    }
    free(remote_addr_copy);
    errno = ECONNREFUSED;
    return -1;
}

int listen_nfl(nfl_sock_full_t *sock, const int backlog) {
    (void)backlog;
    if (sock->type != SOCK_STREAM) {
        nfl_log("Calling listen on non stream sock %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }
    if (sock->remote_addr) { // Already connected
        nfl_log("Calling listen on connected stream sock %s", sock_to_str(sock));
        errno = EINVAL;
        return -1;
    }
    if (!sock->local_addr) {
        /* Linux semantics: listen() on an unbound stream socket auto-binds to a
         * wildcard address with an ephemeral port. */
        const uint16_t port = get_ephemeral_local_port_network_byte_order();
        if (sock->domain == AF_INET) {
            const struct sockaddr_in autobound = { .sin_family = AF_INET, .sin_port = port };
            if (bind_nfl(sock, (const nfl_addr_t *)&autobound, sizeof(autobound)) < 0) {
                return -1;
            }
        } else if (sock->domain == AF_INET6) {
            const struct sockaddr_in6 autobound = { .sin6_family = AF_INET6, .sin6_port = port };
            if (bind_nfl(sock, (const nfl_addr_t *)&autobound, sizeof(autobound)) < 0) {
                return -1;
            }
        } else {
            errno = EOPNOTSUPP;
            return -1;
        }
    }
    sock->is_listening = true;
    nfl_log("listen() success: %s", sock_to_str(sock));
    nfl_sock_listen_priv((const nfl_sock_t *)sock);
    return 0;
}

int accept4_nfl(nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *len, const int flags) {
    const int new_fd = accept_nfl(sock, addr, len);
    if (new_fd < 0) {
        return new_fd;
    }
    // SOCK_NONBLOCK in accept4 flags applies to the *new* accepted fd, not the listening one.
    if (flags & SOCK_NONBLOCK) {
        nfl_sock_full_t *new_sock = get_nfl_sock(new_fd);
        if (new_sock) {
            new_sock->status_flags.blocking = false;
        }
    }
    return new_fd;
}

int tcp_update_pending_connections(nfl_sock_full_t *listening_socket) {
    if (listening_socket->tcp_pending) {
        return 0;
    }

    const int connected_socket_fd = socket_nfl(listening_socket->domain, listening_socket->type, listening_socket->protocol);
    nfl_sock_full_t *connected_socket = get_nfl_sock(connected_socket_fd);
    fd_table_clear(connected_socket_fd);
    connected_socket->references = 0;

    nfl_addr_t *remote_addr = calloc(1, sizeof(nfl_addr_t));
    if (!remote_addr) {
        errno = ENOBUFS;
        return -1;
    }

    // Expose the listener's bound address as sock->local_addr for the callback.
    // The accepted socket gets its own local_addr only on success below. This is
    // a borrowed pointer, so clear it before any free and overwrite it on success.
    connected_socket->local_addr = listening_socket->local_addr;

    if (nfl_tcp_accept((const nfl_sock_t *)connected_socket, remote_addr)) {
        nfl_addr_t *bound_addr;
        if (addr_is_zero_address(listening_socket->local_addr)) {
            bound_addr = generate_local_addr(remote_addr, nfl_addr_get_port_network_byte_order(listening_socket->local_addr));
            if (!bound_addr) {
                connected_socket->local_addr = NULL; // drop the borrowed pointer
                free(remote_addr);
                return -1;
            }
        } else {
            bound_addr = (nfl_addr_t *)malloc(sizeof(nfl_addr_t));
            if (!bound_addr) {
                connected_socket->local_addr = NULL; // drop the borrowed pointer
                free(remote_addr);
                errno = ENOBUFS;
                return -1;
            }
            memcpy(bound_addr, listening_socket->local_addr, sizeof(nfl_addr_t));
        }
        connected_socket->local_addr = bound_addr;
        connected_socket->remote_addr = remote_addr;

        nfl_log("accept pending() 1/2: listening %s", sock_to_str(listening_socket));
        nfl_log("accept pending() success 2/2: connected %s", sock_to_str(connected_socket));

        listening_socket->tcp_pending = connected_socket;
        sock_readiness_changed(listening_socket); // listener is now readable
    } else {
        // fd_table entry was already cleared above, free the sock directly.
        connected_socket->local_addr = NULL; // drop the borrowed pointer before free
        free_nfl_sock(connected_socket);
        free(remote_addr);
    }
    return 0;
}

int accept_nfl(nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *len) {
    if (sock->type != SOCK_STREAM) { // accept only possible on stream sockets
        nfl_log("Accept call on non stream socket: %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }

    if (!sock->is_listening) {
        nfl_log("Accept call on stream socket which is not in listening state: %s", sock_to_str(sock));
        errno = EINVAL;
        return -1;
    }
    assert(sock->local_addr); // Should be set since we are in listening state
    const socklen_t domain_addrlen = get_socket_domain_addrlen(sock->domain);

    tcp_update_pending_connections(sock);
    if (sock->tcp_pending) {
        const int connected_fd = get_available_fd();
        if (connected_fd == -1) {
            errno = EMFILE;
            return -1;
        }
        nfl_sock_full_t *connected_socket = sock->tcp_pending;
        sock->tcp_pending = NULL;
        fd_table_set(connected_fd, connected_socket);

        if (addr) {
            if (*len < domain_addrlen) {
                nfl_log("Accept call with passed sockaddr length too short");
                memcpy(addr, connected_socket->remote_addr, *len);
            } else {
                memcpy(addr, connected_socket->remote_addr, domain_addrlen);
            }
            *len = domain_addrlen;
        }
        return connected_fd;
    }
    if (sock->status_flags.blocking) {
        nfl_log("Blocking accept() on %s", sock_to_str(sock));
        nfl_block_or_exit((const nfl_sock_t *)sock);
        errno = EINTR;
        return -1;
    }
    errno = EAGAIN;
    return -1;
}

ssize_t recvmsg_stream(nfl_sock_full_t *sock, const struct msghdr *msg, const nfl_recv_flags flags) {
    if (!sock->remote_addr) {
        errno = ENOTCONN;
        return -1;
    }
    if (sock->shutdown_read) {
        // recv after shutdown(SHUT_RD) is end-of-stream: return 0, no errno.
        return 0;
    }
    const bool nonblocking = !sock->status_flags.blocking || flags.msg_dontwait;
    /* Enforced inter-packet gap: after a packet was fully consumed, one
     * non-blocking recv reports EAGAIN before the next packet is delivered, so
     * the SUT must re-poll between packets. Blocking recv is exempt. */
    if (nonblocking && sock->recv_gap_pending) {
        sock->recv_gap_pending = false;
        errno = EAGAIN;
        return -1;
    }
    sock_update_recv_buffer(sock);
    /* nfl_receive may have set shutdown_read.
     * Re-check after the buffer update so the current recv returns
     * 0 cleanly instead of falling through to the fatal blocking-recv path. */
    if (sock->shutdown_read) {
        return 0;
    }
    if (!sock->packets_ll) {
        if (nonblocking) {
            errno = EAGAIN;
            return -1;
        }
        nfl_log("blocking recv(/from/msg) on sock without incoming data, %s", sock_to_str(sock));
        nfl_block_or_exit((const nfl_sock_t *)sock);
        errno = EINTR;
        return -1;
    }

    ssize_t n;
    if (flags.msg_trunc && !flags.msg_peek) {
        // TCP MSG_TRUNC: discard up to iov-total bytes from the stream and return that count.
        const size_t to_discard = (size_t)iov_count_bytes(msg->msg_iov, msg->msg_iovlen);
        size_t discarded = 0;
        while (discarded < to_discard) {
            sock_update_recv_buffer(sock);
            if (!sock->packets_ll) {
                break;
            }
            const size_t avail = sock->packets_ll->len - sock->packet_offset;
            const size_t take = avail < (to_discard - discarded) ? avail : (to_discard - discarded);
            sock->packet_offset += take;
            discarded += take;
            if (sock->packet_offset >= sock->packets_ll->len) {
                sock_clear_recv_buffer_and_load_next_packet(sock);
            }
        }
        n = (ssize_t)discarded;
    } else {
        n = socket_recv_iov(sock, msg->msg_iov, msg->msg_iovlen, flags.msg_peek);
    }
    /* Arm the gap once this read drained the current packet (queue now empty),
     * so the next non-blocking recv reports EAGAIN before the following one. */
    if (nonblocking && !flags.msg_peek && !sock->packets_ll) {
        sock->recv_gap_pending = true;
    }
    return n;
}

ssize_t sendmsg_stream(const nfl_sock_full_t *sock, const struct msghdr *msg, const int flags) {
    if (!sock->local_addr || !sock->remote_addr) {
        errno = ENOTCONN;
        return -1;
    }
    // Linux returns EISCONN if a destination is specified on a connected stream socket.
    if (msg->msg_name && msg->msg_namelen) {
        errno = EISCONN;
        return -1;
    }
    if (nfl_send_priv((const nfl_sock_t *)sock, sock->remote_addr, msg->msg_iov, msg->msg_iovlen) == NFL_CONN_CLOSED) {
        // Peer is gone: send(2) raises SIGPIPE (unless MSG_NOSIGNAL) then fails with EPIPE.
        if (!(flags & MSG_NOSIGNAL)) {
            raise(SIGPIPE);
        }
        errno = EPIPE;
        return -1;
    }
    const ssize_t amount_bytes_sent = iov_count_bytes(msg->msg_iov, msg->msg_iovlen);

#if NFL_DEBUG
    char sender_str[SOCKADDR_STR_MAX_LEN];
    char receiver_str[SOCKADDR_STR_MAX_LEN];
    sockaddr_to_str(sock->local_addr, sender_str, sizeof(sender_str));
    sockaddr_to_str(sock->remote_addr, receiver_str, sizeof(receiver_str));
    nfl_log("Sent %ld bytes | from: %s | to %s | %s", amount_bytes_sent, sender_str, receiver_str, sock_to_str(sock));
#endif
    return amount_bytes_sent;
}
