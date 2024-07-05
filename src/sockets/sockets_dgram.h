#ifndef NETFUZZLIB_SOCKETS_DGRAM_H
#define NETFUZZLIB_SOCKETS_DGRAM_H

#include "network_types.h"

int connect_dgram(nfl_sock_t *sock, const nfl_addr_t *addr, socklen_t addrlen);

ssize_t recvmsg_dgram(nfl_sock_t *sock, struct msghdr *msg, int flags);

ssize_t sendmsg_dgram(nfl_sock_t *sock, const struct msghdr *msg, int flags);

#endif // NETFUZZLIB_SOCKETS_DGRAM_H
