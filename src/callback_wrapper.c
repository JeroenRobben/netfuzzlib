#include <sched.h>
#include "callback_wrapper.h"


void nfl_socket_idle_priv(const struct nfl_sock_t *sock) {
    if (nfl_socket_idle) {
        nfl_socket_idle(sock);
    }
}

void nfl_block_or_exit(const struct nfl_sock_t *sock) {
    nfl_socket_idle_priv(sock);
    sched_yield();
}

nfl_conn_result nfl_send_priv(const struct nfl_sock_t *sock, const nfl_addr_t *to,
                              const struct iovec *iov, size_t iovlen) {
    if (nfl_send) {
        return nfl_send(sock, to, iov, iovlen);
    }
    return NFL_CONN_OK;
}

void nfl_sock_close_priv(const struct nfl_sock_t *sock) {
    if (nfl_sock_close) {
        nfl_sock_close(sock);
    }
}

void nfl_sock_listen_priv(const struct nfl_sock_t *sock) {
    if (nfl_sock_listen) {
        nfl_sock_listen(sock);
    }
}

void nfl_sock_bind_priv(const struct nfl_sock_t *sock) {
    if (nfl_sock_bind) {
        nfl_sock_bind(sock);
    }
}
