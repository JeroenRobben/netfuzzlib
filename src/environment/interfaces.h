#ifndef NETFUZZLIB_INTERFACES_H
#define NETFUZZLIB_INTERFACES_H

#include "sockets/network_types.h"
/**
 * Return the nfl_l2_iface_t corresponding to a given interface index (e.g. 1 or 2)
 * Returns NULL if no such device exists.
 * @param index The index of the device to get
 * @return The nfl_l2_iface_t corresponding to the given device index
 */
nfl_l2_iface_t *get_l2_iface_by_index(unsigned int index);

/**
 * Return the nfl_l2_iface_t corresponding to a given interface name (e.g. eth0 or lo)
 * Returns NULL if no such device exists.
 * @param name The name of the device to get
 * @return The nfl_l2_iface_t corresponding to the given device name
 */
nfl_l2_iface_t *get_l2_iface_by_name(const char *name);

/**
 * Add an nfl_l3_iface_t to an nfl_l2_iface_t.
 * @param l2_iface The nfl_l2_iface_t to add l3_iface to
 * @param l3_iface The nfl_l3_iface_t to add
 */
void add_l3_iface_to_l2_iface(nfl_l2_iface_t *l2_iface, nfl_l3_iface_t *l3_iface);

/**
 * Return whether a given address is eligible for binding
 * to a given sock, e.g. it is the address of an existing interface (in the nfl_l3_iface_t list),
 * is a broadcast or multicast address for a network we're on, applicable for the given sock
 * or is a special address like 0.0.0.0 or ::0, (INADDR_ANY).
 */
bool can_bind_to_address(nfl_sock_t *sock, const nfl_addr_t *addr);

/**
 * Get the ipv4 local broadcast address of an ipv4 nfl_l3_iface_t
 * @param l3_iface The ipv4 nfl_l3_iface_t to get the broadcast address for
 * @param broadcast The sockaddr_in to write the broadcast address to
 */
void get_l3_iface_broadcast_addr(const nfl_l3_iface_t *l3_iface, struct sockaddr_in *broadcast);

/**
  * Return the amount of L3 ipv4 interfaces
  * @return The amount of L3 ipv4 interfaces
  */
int get_l3_iface_ipv4_count();

/**
 * Return whether a given l2_iface is the loopback interface
 * @param l2_iface The l2_iface to check
 * @return True iff the given l2_iface is the loopback interface
 */
bool l2_iface_is_loopback(nfl_l2_iface_t *l2_iface);

/**
 * Add a loopback device (127.0.0.1 / ::1)
 */
int add_loopback_device();

#endif //NETFUZZLIB_INTERFACES_H
