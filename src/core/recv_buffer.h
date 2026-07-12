#ifndef NETFUZZLIB_RECV_BUFFER_H
#define NETFUZZLIB_RECV_BUFFER_H

#include "network_types.h"
#include <netfuzzlib/callbacks.h>
#include <unistd.h>
#include <arpa/inet.h>

enum ENDIANNESS { LE,
                  BE };

void sock_update_recv_buffer(nfl_sock_full_t *sock);

size_t sock_recv_buffer_bytes_available(nfl_sock_full_t *sock);

ssize_t socket_recv_iov(nfl_sock_full_t *sock, const struct iovec *dst_iov_array, size_t dst_iov_array_len, bool peek);

nfl_recv_pkt *alloc_recv_pkt(size_t len_bytes);

/**
 * Append a nfl_recv_pkt to the end of the receive queue of a socket
 * @param socket The socket to add a packet to
 * @param packet The packet to add to the socket. Must be created with 'alloc_recv_pkt()'.
 */
void sock_append_packet(nfl_sock_full_t *socket, nfl_recv_pkt *packet);

void sock_readiness_changed(nfl_sock_full_t *sock);


void nfl_free_pkt(nfl_recv_pkt *packet);

void free_packet_ll(nfl_recv_pkt *packet);

void sock_clear_recv_buffer_and_load_next_packet(nfl_sock_full_t *socket);

#define NETWORK_DEVICE_STR_MAX_LEN 200

char *network_device_to_string(const nfl_l2_iface_t *device, char *buf, size_t len);

/**
 * Format an L3 interface address as a human-readable string into the caller-provided buffer.
 * @return buf
 */
char *network_device_address_to_string(const nfl_l3_iface_t *address, char *buf, size_t len);

/**
 * Return whether an ipv4 address is within a given subnet
 * All l3_interfaces are given in network byte order.
 * @param network The network address
 * @param netmask The subnet mask of the network
 * @param addr The address to check whether it is in the subnet
 * @return True if addr is within the subnet, e.g. addr=192.168.0.5, network=192.168.0.0 and netmask=255.255.255.0
 */
bool ipv4_addr_within_subnet(const struct in_addr *network, const struct in_addr *netmask, const struct in_addr *addr);

/**
 * Return whether an ipv6 address is within a given subnet
 * All l3_interfaces are given in network byte order.
 * @param network The network address,
 * @param prefix The network prefix length, in bits
 * @param addr The address to check whether it is in the subnet
 * @return True if addr is within the subnet, e.g. addr=2001::, prefix=112, addr=2001::5
 */
bool ipv6_addr_within_subnet(const struct in6_addr *network, unsigned int prefix, const struct in6_addr *addr);

/**
 * Convert a nfl_sock_full_t to a human-readable string, for debugging purposes.
 * The string is returned in a statically allocated buffer, which subsequent calls will overwrite.
 * @param sock The socket to get debug info for.
 * @return A string describing the socket in human readable form.
 */
char *sock_to_str(const struct nfl_sock_full_t *sock);

#define SOCKADDR_STR_MAX_LEN (INET6_ADDRSTRLEN + sizeof("|:65535"))

/**
 * Get a sockaddr structure as a human readable string, e.g. 127.0.0.1:5555, for debugging purposes
 * @param addr sockaddr structure, domain can be AF_INET, AF_INET6 or AF_NETLINK
 * @param buf buffer to hold the resulting string
 * @param len The size in bytes of buf
 * @return buf
 */
char *sockaddr_to_str(const nfl_addr_t *addr, char *buf, size_t len);

/**
 * Get a sockaddr structure as a human readable string, e.g. 127.0.0.1:5555, for debugging purposes
 * The string is returned in a statically allocated buffer, which subsequent calls will overwrite.
 * @param addr sockaddr structure, domain can be AF_INET, AF_INET6 or AF_NETLINK
 * @return A string describing the ip endpoint in human readable form.
 */
char *sockaddr_to_str_static_alloc(const nfl_addr_t *addr);

#endif // NETFUZZLIB_RECV_BUFFER_H
