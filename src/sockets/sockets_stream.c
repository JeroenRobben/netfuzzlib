#include <netfuzzlib/module_api.h>
#include "hooks/hooks.h"
#include "sockets_util.h"
#include "sockets.h"
#include "environment/routing.h"
#include "netfuzzlib/util.h"
#include <asm-generic/errno.h>
#include <assert.h>
#include <errno.h>
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
static nfl_addr_t *generate_local_addr(const nfl_addr_t *remote_addr, uint16_t port_network_byte_order) {
    nfl_l3_iface_t *local_interface = routing_table_lookup(remote_addr);
    if (!local_interface) {
        errno = ENETUNREACH;
        return NULL;
    }
    uint16_t port;

    if(port_network_byte_order == 0) {
        port = get_ephemeral_local_port_network_byte_order();
        if (port == 0) {
            errno = EADDRNOTAVAIL;
            return NULL;
        }
    }
    else {
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

int connect_stream(nfl_sock_t *sock, const nfl_addr_t *remote_addr, socklen_t addrlen) {
    if (!remote_addr) {
        errno = EINVAL;
        return -1;
    }

    if (sock->is_listening) { //Can't call connect on listening sock
        errno = EINVAL;
        return -1;
    }

    if (remote_addr->s.sa_family == AF_UNSPEC) {
        if (sock->remote_addr) {
            free((void *)remote_addr);
            sock->remote_addr = NULL;
        }
        if (sock->packets_ll) {
            free_packet_ll(sock->packets_ll);
            sock->packets_ll = NULL;
            sock->packet_offset = 0;
        }
        return 0;
    }

    if (sock->remote_addr) { //Already connected
        errno = EISCONN;
        return -1;
    }

    if (addrlen != get_socket_domain_addrlen(sock->domain)) {
        errno = EINVAL;
        return -1;
    }

    nfl_addr_t *bound_addr = sock->local_addr;
    if (!bound_addr) {
        bound_addr = generate_local_addr(remote_addr, 0);
        if (!bound_addr) {
            return -1;
        }
    }

    nfl_addr_t *remote_addr_copy = (nfl_addr_t *)malloc(sizeof(nfl_addr_t));
    if (!remote_addr_copy) {
        if (sock->local_addr != bound_addr) {
            free(bound_addr);
        }
        errno = ENOBUFS;
        return -1;
    }
    memcpy(remote_addr_copy, remote_addr, addrlen);

    if (nfl_tcp_connect((const nfl_sock_module_t *)sock, bound_addr, remote_addr_copy)) {
        sock->remote_addr = remote_addr_copy;
        sock->local_addr = bound_addr;
        nfl_log_info("connect() success: %s", sock_to_str(sock));
        return 0;
    } else {
        if (sock->local_addr != bound_addr) {
            free(bound_addr);
        }
        errno = ECONNREFUSED;
        return -1;
    }
}

int listen_nfl(nfl_sock_t *sock, int backlog) {
    if (sock->type != SOCK_STREAM) {
        nfl_log_warn("Calling listen on non stream sock %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }
    if (!sock->local_addr) {
        nfl_log_warn("Calling listen on non bound stream sock %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }
    if (sock->remote_addr) {
        nfl_log_warn("Calling listen on connected stream sock %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }
    sock->is_listening = true;
    nfl_log_info("listen() success: %s", sock_to_str(sock));
    return 0;
}

int accept4_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *len, int flags) {
    if (IS_FLAG_SET(flags, SOCK_NONBLOCK)) {
        sock->status_flags.blocking = false;
    }
    return accept_nfl(sock, addr, len);
}


int tcp_update_pending_connections(nfl_sock_t *listening_socket) {
    if (listening_socket->tcp_pending) {
        return 0;
    }

    int connected_socket_fd = socket_nfl(listening_socket->domain, listening_socket->type, listening_socket->protocol);
    nfl_sock_t *connected_socket = get_nfl_sock(connected_socket_fd);

    nfl_addr_t *remote_addr = calloc(1, sizeof(nfl_addr_t));
    if (!remote_addr) {
        errno = ENOBUFS;
        return -1;
    }

    if (nfl_tcp_accept((const nfl_sock_module_t *)connected_socket, listening_socket->local_addr, remote_addr)) {
        nfl_addr_t *bound_addr;
        if(addr_is_zero_address(listening_socket->local_addr)){
            bound_addr = generate_local_addr(remote_addr, nfl_addr_get_port_network_byte_order(listening_socket->local_addr));
            if(!bound_addr){
                free(remote_addr);
                return -1;
            }
        }
        else {
            bound_addr = (nfl_addr_t *)malloc(sizeof(nfl_addr_t));
            if (!bound_addr) {
                free(remote_addr);
                errno = ENOBUFS;
                return -1;
            }
            memcpy(bound_addr, listening_socket->local_addr, sizeof(nfl_addr_t));
        }
        connected_socket->local_addr = bound_addr;
        connected_socket->remote_addr = remote_addr;

        nfl_log_info("accept pending() 1/2: listening %s", sock_to_str(listening_socket));
        nfl_log_info("accept pending() success 2/2: connected %s", sock_to_str(connected_socket));

        listening_socket->tcp_pending = connected_socket;
    } else {
        close(connected_socket_fd);
        free(remote_addr);
    }
    return 0;
}

int accept_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *len) {
    if (sock->type != SOCK_STREAM) { // accept only possible on stream sockets
        nfl_log_warn("Accept call on non stream socket: %s", sock_to_str(sock));
        errno = EOPNOTSUPP;
        return -1;
    }

    if (!sock->is_listening) {
        nfl_log_warn("Accept call on stream socket which is not in listening state: %s", sock_to_str(sock));
        errno = EINVAL;
        return -1;
    }
    assert(sock->local_addr); //Should be set since we are in listening state
    socklen_t domain_addrlen = get_socket_domain_addrlen(sock->domain);

    tcp_update_pending_connections(sock);
    if (sock->tcp_pending) {
        int connected_fd = get_available_fd();
        if (connected_fd == -1) {
            errno = EMFILE;
            return -1;
        }
        nfl_sock_t *connected_socket = sock->tcp_pending;
        sock->tcp_pending = NULL;
        fd_table_set(connected_fd, connected_socket);

        if (addr) {
            if (*len < domain_addrlen) {
                nfl_log_warn("Accept call with passed sockaddr length too short");
                memcpy(addr, connected_socket->remote_addr, *len);
            } else {
                memcpy(addr, connected_socket->remote_addr, domain_addrlen);
            }
            *len = domain_addrlen;
        }
        return connected_fd;
    } else {
        if (sock->status_flags.blocking) {
            nfl_log_info("Blocking accept() on %s", sock_to_str(sock));
            nfl_end_priv();
            __builtin_unreachable();
        } else {
            errno = EAGAIN;
            return -1;
        }
    }
}

ssize_t recvmsg_stream(nfl_sock_t *sock, struct msghdr *msg, int flags) {
    if (!sock->remote_addr) {
        errno = ENOTCONN;
        return -1;
    }
    sock_update_recv_buffer(sock);
    if (sock->shutdown_read) {
        errno = EPIPE;
        return -1;
    }
    if (!sock->packets_ll) {
        if (!sock->status_flags.blocking || IS_FLAG_SET(flags, MSG_DONTWAIT)) {
            errno = EAGAIN;
            return 0;
        } else {
            nfl_log_fatal("blocking recv(/from/msg) on sock without incoming data, %s", sock_to_str(sock));
            nfl_end_priv();
        }
    }

    if (IS_FLAG_SET(flags, MSG_TRUNC)) {
        sock_clear_recv_buffer_and_load_next_packet(sock);
        return 0;
    }
    return socket_recv_iov(sock, msg->msg_iov, msg->msg_iovlen, IS_FLAG_SET(flags, MSG_PEEK));
}

ssize_t sendmsg_stream(nfl_sock_t *sock, const struct msghdr *msg, int flags) {
    if (!sock->local_addr || !sock->remote_addr) {
        errno = ENOTCONN;
        return -1;
    }
    //TODO fill in msghdr
    ssize_t amount_bytes_sent = nfl_send((const nfl_sock_module_t *)sock, sock->local_addr, sock->remote_addr, msg->msg_iov, msg->msg_iovlen);

#if NFL_DEBUG
    char sender_str[SOCKADDR_STR_MAX_LEN], receiver_str[SOCKADDR_STR_MAX_LEN];
    sockaddr_to_str(sock->local_addr, sender_str, sizeof(sender_str));
    sockaddr_to_str(sock->remote_addr, receiver_str, sizeof(receiver_str));
    nfl_log_info("Sent %d bytes | from: %s | to %s | %s", amount_bytes_sent, sender_str, receiver_str, sock_to_str(sock));
#endif
    return amount_bytes_sent;
}
