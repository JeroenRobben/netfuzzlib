#ifndef NETFUZZLIB_CALLBACK_WRAPPER_H
#define NETFUZZLIB_CALLBACK_WRAPPER_H

#include "netfuzzlib/callbacks.h"
#include "netfuzzlib/types.h"

// Invoke the optional nfl_socket_idle() callback for the idle sock. With no
// callback, does nothing and the target keeps running. May not return, since the
// callback can exit().
void nfl_socket_idle_priv(const struct nfl_sock_t *sock);

// A blocking read or accept on sock found nothing. Consults nfl_socket_idle_priv
// (whose callback may exit()). If it returns, yields so the caller reports EINTR
// and the target retries.
void nfl_block_or_exit(const struct nfl_sock_t *sock);

void nfl_sock_close_priv(const struct nfl_sock_t *sock);

nfl_conn_result nfl_send_priv(const struct nfl_sock_t *sock, const nfl_addr_t *to,
                              const struct iovec *iov, size_t iovlen);

void nfl_sock_listen_priv(const struct nfl_sock_t *sock);

void nfl_sock_bind_priv(const struct nfl_sock_t *sock);

#endif // NETFUZZLIB_CALLBACK_WRAPPER_H
