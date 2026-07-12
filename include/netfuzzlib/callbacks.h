#ifndef NETFUZZLIB_CALLBACKS_H
#define NETFUZZLIB_CALLBACKS_H

#include <netfuzzlib/api.h>
#include <stdbool.h>
#include <sys/uio.h>

// Optional. Called at program start, before main().
__attribute__((weak)) int nfl_setup();

// Decide whether an outgoing TCP connect() to remote_addr succeeds.
// The local address is sock->local_addr.
bool nfl_tcp_connect(const nfl_sock_t *sock, const nfl_addr_t *remote_addr);

// Decide whether accept() on a TCP socket should succeed. Also called
// when poll/select probes a listener for incoming connections. On success, fill
// remote_addr with the peer. The listener's bound address is sock->local_addr.
bool nfl_tcp_accept(const nfl_sock_t *sock, nfl_addr_t *remote_addr);

typedef enum nfl_conn_result {
    NFL_CONN_OK,     // The connection is alive.
    NFL_CONN_CLOSED, // The connection is closed..
} nfl_conn_result;

// Optional. Called when the target sends data. The sender is sock->local_addr,
// the destination is `to`.
// For TCP, you can return NFL_CONN_CLOSED to indicate the peer closed the connection.
__attribute__((weak)) nfl_conn_result nfl_send(const nfl_sock_t *sock, const nfl_addr_t *to,
                                               const struct iovec *iov, size_t iovlen);

// Called when the target reads or probes for data and the buffer is empty.
// Allocate a packet with nfl_alloc_pkt(), fill its buffer, set *pkt to it, and
// return NFL_CONN_OK. The framework then owns and frees it. 
// Set *pkt to NULL for nothing to deliver right now. 
// For TCP, you can return NFL_CONN_CLOSED to indicate the peer closed the connection.
// For UDP, you need to fill in `info` with the source IP+port, and optionally the destination and
// interface for IP_PKTINFO. For TCP sockets ignores `info`.
nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info);

// Optional. Called when the last fd reference to a socket is closed.
__attribute__((weak)) void nfl_sock_close(const nfl_sock_t *sock);

// Optional. Called after a listen() on a TCP socket.
__attribute__((weak)) void nfl_sock_listen(const nfl_sock_t *sock);

// Optional. Called after a succesfull bind()
__attribute__((weak)) void nfl_sock_bind(const nfl_sock_t *sock);

// Fires when a modelled socket goes idle: nfl_receive returned no more data for it
// and the target did a blocking call on it or 10 non-blocking reads/polls.
// (See nfl_set_max_idle_polls to change this number).
__attribute__((weak)) void nfl_socket_idle(const nfl_sock_t *sock);

#endif // NETFUZZLIB_CALLBACKS_H
