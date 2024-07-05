#ifndef NETFUZZLIB_SOCKETS_COMMON_H
#define NETFUZZLIB_SOCKETS_COMMON_H

#include "../environment/network_env.h"
#include <bits/wordsize.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdarg.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>

/*
 * Return whether a given combination of socket domain, type and protocol is supported by the model.
 * See man 2 socket
 */
bool is_socket_supported(int domain, int type, int protocol);

uint16_t get_ephemeral_local_port_network_byte_order();

/*
 * Used when calling connect() without a prior bind call
 * First check whether the target address to connect to is in the local subnet of an existing device address.
 * If this is the case, bind to the address of this interface.
 * Otherwise, bind to the address of the default gateway.
 * Always use a random ephemeral port.
 */
int autobind_udp(nfl_sock_t *socket, const nfl_addr_t *remote_addr);

#endif /*NETFUZZLIB_SOCKETS_COMMON_H*/