#ifndef NETFUZZLIB_SOCKETS_UTIL_H
#define NETFUZZLIB_SOCKETS_UTIL_H

#include "network_types.h"
#include <netfuzzlib/module_api.h>
#include <stddef.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

enum ENDIANNESS { LE, BE };

/**
 * Update the receive buffer of a given sock.
 * If the buffer still has bytes available, do nothing
 * Otherwise, set the buffer to the next packet queued for the sock
 * If no packets are queued for this sock, request a new packet from the fuzzing module.
 * @param sock The sock for which the receive buffer should be updated.
 */
void sock_update_recv_buffer(nfl_sock_t *sock);

/**
 * Get the amount of bytes available in the current packet of a sock
 * @param sock
 * @return
 */
size_t sock_recv_buffer_bytes_available(nfl_sock_t *sock);

/**
 * Read data from a sock packet buffer to a given array of iovs
 * @param sock The sock to receive data on
 * @param dst_iov_array An array of iovecs
 * @param dst_iov_array_len The amount of iovecs in dst_iov_array
 * @param peek If set to true, do not remove the read data from the sock receive buffer
 * @return  The amount of bytes read. Returns 0 if no data is available
 */
ssize_t socket_recv_iov(nfl_sock_t *sock, struct iovec *dst_iov_array, size_t dst_iov_array_len, bool peek);

/**
 * Append a nfl_pkt to the end of the receive queue of a socket
 * @param socket The socket to add a packet to
 * @param packet The packet to add to the socket. Must be created with 'nfl_alloc_pkt()'.
 */
void sock_append_packet(nfl_sock_t *socket, nfl_pkt *packet);

/**
 * Returns true if for the current network environment all packets have been consumed by the client application.
 */
bool all_packets_consumed();

/**
 * Free a network packet. packet->next will be ignored.
 */
void nfl_free_packet(nfl_pkt *packet);

/**
 * Free a linked list of network packets.
 */
void free_packet_ll(nfl_pkt *packet);

/**
 * Get the length in bytes of the sockaddr structure for a given socket domain.
 * E.g., returns sizeof(struct sockaddr_in) if domain == AF_INET
 */
socklen_t get_socket_domain_addrlen(int domain);

/**
 * Remove and free the first queued packet in a socket and set the socket packets offset to 0
 * Does nothing when the passed socket does not have any packets queued
 * @param socket The socket to remove the current packet from
 */
void sock_clear_recv_buffer_and_load_next_packet(nfl_sock_t *socket);

char *network_device_to_string(nfl_l2_iface_t *device);
char *network_device_address_to_string(nfl_l3_iface_t *address);

/**
 * Return whether an ipv4 address is within a given subnet
 * All l3_interfaces are given in network byte order.
 * @param network The network address
 * @param netmask The subnet mask of the network
 * @param addr The address to check whether it is in the subnet
 * @return True iff addr is within the subnet, e.g. addr=192.168.0.5, network=192.168.0.0 and netmask=255.255.255.0
 */
bool ipv4_addr_within_subnet(const struct in_addr *network, const struct in_addr *netmask, const struct in_addr *addr);

/**
 * Return whether an ipv6 address is within a given subnet
 * All l3_interfaces are given in network byte order.
 * @param network The network address,
 * @param prefix The network prefix length, in bits
 * @param addr The address to check whether it is in the subnet
 * @return True iff addr is within the subnet, e.g. addr=2001::, prefix=112, addr=2001::5
 */
bool ipv6_addr_within_subnet(const struct in6_addr *network, unsigned int prefix, const struct in6_addr *addr);

/**
 * Convert a nfl_sock_t to a human-readable string, for debugging purposes.
 * The string is returned in a statically allocated buffer, which subsequent calls will overwrite.
 * @param sock The socket to get debug info for.
 * @return A string describing the socket in human readable form.
 */
char *sock_to_str(const struct nfl_sock_t *sock);

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

#endif // NETFUZZLIB_SOCKETS_UTIL_H
