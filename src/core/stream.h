#ifndef NETFUZZLIB_STREAM_H
#define NETFUZZLIB_STREAM_H

#include "network_types.h"

int connect_stream(nfl_sock_full_t *sock, const nfl_addr_t *remote_addr, socklen_t addrlen);

/**
 * Update the pending connections of a listening socket. This will invoke the fuzzing module if no current pending
 * connection exists.
 * @param listening_socket The listening socket
 * @return 0 on success, -1 on error
 */
int tcp_update_pending_connections(nfl_sock_full_t *listening_socket);

ssize_t recvmsg_stream(nfl_sock_full_t *sock, const struct msghdr *msg, nfl_recv_flags flags);

ssize_t sendmsg_stream(const nfl_sock_full_t *sock, const struct msghdr *msg, int flags);

#endif // NETFUZZLIB_STREAM_H
