#ifndef NETFUZZLIB_INTERFACES_H
#define NETFUZZLIB_INTERFACES_H

#include "network_types.h"
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
bool can_bind_to_address(const nfl_sock_full_t *sock, const nfl_addr_t *addr);

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
 * @return True if the given l2_iface is the loopback interface
 */
bool l2_iface_is_loopback(const nfl_l2_iface_t *l2_iface);

/**
 * Return whether any non-loopback L2 interface has been configured, i.e. the
 * module built a topology of its own rather than relying on the default.
 */
bool env_has_non_loopback_iface(void);

/**
 * Add a loopback device (127.0.0.1 / ::1)
 */
int add_loopback_device();

/* Module-facing network-environment construction.
 * Public API a module's nfl_setup uses to build its topology.
 * A module that configures no interface gets the host's network devices
 * imported by default (see nfl_import_host_network_devices). */

/**
 * Add a new network device.
 * @param name  Zero terminated string, length (incl. terminator) <= IF_NAMESIZE
 * @param flags Device flags, see man 7 netdevice, SIOCGIFFLAGS
 * @param mtu The MTU of the device
 * @param hw_addr MAC address of the new device, size must be ETHER_ADDR_LEN
 * @param hw_broadcast_addr MAC broadcast address, size must be ETHER_ADDR_LEN
 * @param device_index Out: index of the newly created device. Input ignored.
 * @return 0 on success, -1 on failure
 */
int nfl_add_l2_iface(const char *name, short flags, int mtu, const char *hw_addr, const char *hw_broadcast_addr, unsigned int *device_index);

/**
 * Add an ipv4 address to a network device.
 * @param device_index The device to add the address to.
 * @param addr_text IPv4 address, e.g. "192.168.1.1"
 * @param netmask_text IPv4 subnet mask, e.g. "255.255.255.0"
 * @return 0 on success, -1 on failure
 */
int nfl_add_l3_iface_ipv4(unsigned int device_index, const char *addr_text, const char *netmask_text);

/**
 * Add an ipv6 address to a network device.
 * @param device_index The device to add the address to.
 * @param addr_text IPv6 address, e.g. "2001:0000::"
 * @param prefix_length Network prefix length in bits
 * @param scope Network scope, e.g. 0x0 for global or 0x20 for link
 * @return 0 on success, -1 on failure
 */
int nfl_add_l3_iface_ipv6(unsigned int device_index, const char *addr_text, int prefix_length, uint32_t scope);

/**
 * Set the default gateway for IPv4 packets. Must be within the subnet of a
 * configured address of the outgoing device, else an error is returned.
 * @param gateway_addr_text IPv4 gateway, e.g. "192.168.0.1"
 * @param device_index Device to which default-gateway packets are sent.
 * @return 0 on success, -1 otherwise
 */
int nfl_set_ipv4_default_gateway(const char *gateway_addr_text, unsigned int device_index);

/**
 * Set the default gateway for IPv6 packets. Must be within the subnet of a
 * configured address of the outgoing device, else an error is returned.
 * @param gateway_addr_text IPv6 gateway, e.g. "2001:41d0:701:1100::1"
 * @param device_index Device to which default-gateway packets are sent.
 * @return 0 on success, -1 otherwise
 */
int nfl_set_ipv6_default_gateway(const char *gateway_addr_text, unsigned int device_index);

/**
 * Import the host's L2/L3 network devices (interfaces, addresses, default
 * gateways) into the model by reading /sys and /proc. Names that already exist
 * (notably the auto-added "lo") are skipped, so this composes with the
 * nfl_add_* calls above.
 *
 * This is the default: a module that configures no interface of its own gets
 * this called automatically. Call it explicitly only to import the host
 * topology *in addition* to interfaces the module adds itself.
 */
void nfl_import_host_network_devices();

/* Interceptor-facing if_* entry points (impls in interfaces.c). */
unsigned int if_nametoindex_nfl(const char *name);
char *if_indextoname_nfl(unsigned int index, char *ifname);
struct if_nameindex *if_nameindex_nfl(void);
void if_freenameindex_nfl(struct if_nameindex *ptr);

#endif // NETFUZZLIB_INTERFACES_H
