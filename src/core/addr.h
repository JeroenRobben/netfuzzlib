#ifndef NETFUZZLIB_ADDR_H
#define NETFUZZLIB_ADDR_H
#include "netfuzzlib/types.h"
#include <stdbool.h>
#include <stdint.h>
#include <sys/socket.h>

/**
 * Get the size of a sockaddr_in or sockaddr_in6 struct
 * @param domain The domain of the socket, AF_INET | AF_INET6
 * @return The size of the sockaddr struct
 */
socklen_t get_socket_domain_addrlen(int domain);

/**
 * Check if an address is the zero address (0.0.0.0 | ::0)
 * @param addr The address to check
 * @return True if the address is the zero address
 */
bool addr_is_zero_address(const nfl_addr_t *addr);

/**
 * Check if two IP endpoints match. This is the case if both sockets are of the same IP version (4 | 6), both port numbers are equal
 * and both IP addresses are equal OR the zero address (0.0.0.0 | ::0)
 * @param addr1 The first endpoint
 * @param addr2 The second endpoint
 * @return True if the endpoints match
 */
bool ip_endpoints_match(const nfl_addr_t *addr1, const nfl_addr_t *addr2);

/**
 * Get the total amount of bytes in an iovec array
 * @param iov The iovec array
 * @param iovlen The amount of iovec structs in the array
 * @return The total amount of bytes in the array
 */
ssize_t iov_count_bytes(const struct iovec *iov, size_t iovlen);

/**
 * Get the port number of an nfl_addr_t address
 * @param addr The address to get the port number from
 * @return The port number
 */
uint16_t nfl_addr_get_port_network_byte_order(const nfl_addr_t *addr);

#endif // NETFUZZLIB_ADDR_H
