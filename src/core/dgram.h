#ifndef NETFUZZLIB_DGRAM_H
#define NETFUZZLIB_DGRAM_H

#include "network_types.h"

int connect_dgram(nfl_sock_full_t *sock, const nfl_addr_t *addr, socklen_t addrlen);

ssize_t recvmsg_dgram(nfl_sock_full_t *sock, struct msghdr *msg, nfl_recv_flags flags);

ssize_t sendmsg_dgram(nfl_sock_full_t *sock, const struct msghdr *msg);

#endif // NETFUZZLIB_DGRAM_H
