#ifndef NETFUZZLIB_SOCKETS_RTNETLINK_H
#define NETFUZZLIB_SOCKETS_RTNETLINK_H

#include "network_types.h"

typedef struct netlink_msg_ll {
    struct nl_msg *msg;
    struct netlink_msg_ll *next;
} netlink_msg_ll;

ssize_t recvmsg_netlink(nfl_sock_t *socket, struct msghdr *msg, int flags);

ssize_t sendmsg_netlink(nfl_sock_t *socket, const struct msghdr *msg, int flags);

#endif // NETFUZZLIB_SOCKETS_RTNETLINK_H
