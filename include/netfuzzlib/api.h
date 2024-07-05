#ifndef MODULE_CONFIG_FILE_MODULE_API_PROVIDED_H
#define MODULE_CONFIG_FILE_MODULE_API_PROVIDED_H

#include <netfuzzlib/log.h>
#include <netfuzzlib/types.h>
#include <stdint.h>
#include <sys/uio.h>

#define nfl_exit_log(error_code, ...) \
    do {                              \
        nfl_log_fatal(__VA_ARGS__);   \
        exit(error_code);             \
    } while (0)

/**
 * A set of file descriptors reserved for netfuzzlib internal use.
 * Netfuzzlib will attempt to block the SUT from blocking file descriptors within this range
 * Explicit close() calls on file descriptors within this range can be done with close_native();
 */
#define NFL_RESERVED_FD_START 1000
#define NFL_RESERVED_FD_MODULE_START (NFL_RESERVED_FD_START + 2) // File descriptors reserved for module use
#define NFL_RESERVED_FD_MAX 1010

/**
 * Add a new network device.
 * @param name  Must be a zero terminated string with length (including terminator) <= IF_NAMESIZE
 * @param flags The flags of the device, see man 7 netdevice, SIOCGIFFLAGS
 * @param mtu The MTU of the device
 * @param hw_addr The MAC address of the newly created device, size must be ETHER_ADDR_LEN
 * @param hw_broadcast_addr The MAC broadcast address of the newly created device, size must be ETHER_ADDR_LEN
 * @param device_index If successful, device_index will hold the index of the newly created device. The provided value is ignored.
 * @return 0 in case of success, -1 in case of failure
 */
int nfl_add_l2_iface(const char *name, short flags, int mtu, const char *hw_addr, const char *hw_broadcast_addr, unsigned int *device_index);

/**
 * Add an ipv4 address to a network device.
 * @param device_index The index of the device to add the network interface to.
 * @param addr_text The IPv4 address to add in human-readable format, e.g. "192.168.1.1"
 * @param netmask_text The IPv4 subnet mask in human-readable format, e.g. "255.255.255.0"
 * @return 0 in case of success, -1 in case of failure
 */
int nfl_add_l3_iface_ipv4(unsigned int device_index, const char *addr_text, const char *netmask_text);

/**
 * Add an ipv6 address to a network device.
 * @param device_index The index of the device to add the network interface to.
 * @param addr_text The IPv6 address to add in human-readable format, e.g. "2001:0000::"
 * @param prefix_length The network prefix length in amount of bits
 * @param scope The network scope, e.g. 0x0 for global or 0x20 for link
 * @return 0 in case of success, -1 in case of failure
 */
int nfl_add_l3_iface_ipv6(unsigned int device_index, const char *addr_text, int prefix_length, uint32_t scope);

/**
 * Set the default gateway for IPv4 packets
 * @param gateway_addr_text "The ipv4 address of the gateway, e.g. 192.168.0.1".
 * Must be within the subnet of a configured address of the selected outgoing network device, or an error will be returned
 * @param device_index The index of the device to which packets for the default gateway will be sent.
 * @return 0 in case of success, -1 otherwise
 */
int nfl_set_ipv4_default_gateway(const char *gateway_addr_text, unsigned int device_index);

/**
 * Set the default gateway for IPv6 packets
 * @param gateway_addr_text "The ipv6 address of the gateway, e.g. 2001:41d0:701:1100::1".
 * Must be within the subnet of a configured address of the selected outgoing network device, or an error will be returned
 * @param device_index The index of the device to which packets for the default gateway will be sent.
 * @return 0 in case of success, -1 otherwise
 */
int nfl_set_ipv6_default_gateway(const char *gateway_addr_text, unsigned int device_index);

/**
 * Configure whether processed network packets should be free'd. Enabled by default.
 * @param free_enabled True if processed network packets should be free'd, false otherwise.
 */
void nfl_set_free_pkts(bool free_enabled);

/**
 * Allocate a new network packet
 * @param len_bytes The size of the buffer in the packet's iovec.
 * @return A pointer to the new packet, or NULL if no packet could be allocated
 */
nfl_pkt *nfl_alloc_pkt(size_t len_bytes);

/**
 * Normally, the model initialisation code is run before the program's entrypoint (main()) is called,
 * by placing it's initialisation routine in the .init section (see src/init.c).
 * For some applications this could interact with other instrumentation: in this case one can compile the model
 * with definition -DINITIALIZE_NETWORK_MODEL_MANUALLY and call nfl_init_manual() before any code of the target is executed.
 */
void nfl_init_manual();

#endif //MODULE_CONFIG_FILE_MODULE_API_PROVIDED_H
