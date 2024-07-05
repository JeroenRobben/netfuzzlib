#ifndef NETFUZZLIB_ROUTING_H
#define NETFUZZLIB_ROUTING_H

#include "sockets/network_types.h"

/**
 * Get the local interface which would be used for sending a packet to a given destination
 * @param dest_addr The destination address of the packet. Port is ignored
 * @return A pointer to the nfl_l3_iface_t which would be used as outgoing interface for the packet, or NULL if no route to dest_addr exists
 */
nfl_l3_iface_t *routing_table_lookup(const nfl_addr_t *dest_addr);

/**
 * Get the local interface which would be used for sending a packet to a given destination
 * @param dest_addr The destination address of the packet
 * @return A pointer to the nfl_l3_iface_t which would be used as outgoing interface for the packet, or NULL if no route to dest_addr exists
 */
nfl_l3_iface_t *routing_table_lookup_ipv4(const struct in_addr *dest_addr);

/**
 * Get the local interface which would be used for sending a packet to a given destination
 * @param dest_addr The destination address of the packet
 * @return A pointer to the nfl_l3_iface_t which would be used as outgoing interface for the packet, or NULL if no route to dest_addr exists
 */
nfl_l3_iface_t *routing_table_lookup_ipv6(const struct in6_addr *dest_addr);

#endif //NETFUZZLIB_ROUTING_H
