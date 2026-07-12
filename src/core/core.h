#ifndef NETFUZZLIB_CORE_H
#define NETFUZZLIB_CORE_H
#include "network_types.h"

uint16_t get_ephemeral_local_port_network_byte_order();

/**
 * Used when calling connect() without a prior bind call
 * First check whether the target address to connect to is in the local subnet of an existing device address.
 * If this is the case, bind to the address of this interface.
 * Otherwise, bind to the address of the default gateway.
 * Always use a random ephemeral port.
 */
int autobind_udp(nfl_sock_full_t *socket, const nfl_addr_t *remote_addr);

#endif /*NETFUZZLIB_CORE_H*/