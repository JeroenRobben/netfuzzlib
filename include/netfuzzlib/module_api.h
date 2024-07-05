#ifndef NETFUZZLIB_MODULE_API_H
#define NETFUZZLIB_MODULE_API_H

#include <netfuzzlib/api.h>
#include <sys/uio.h>
#include <stdlib.h>

/**
 * Initialize this module, called once during environment setup.
 * Usually adding network interfaces happens here.
 */
int nfl_initialize();

/**
 * Define whether an attempted outgoing tcp connection should succeed
 * Parameters local_addr and remote_addr are guaranteed to be of the same type, sockaddr_in or sockaddr_in6
 * @param local_addr The local address of the sock in case the connect would be successful.
 * @param remote_addr The remote address of the attempted connection.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_connect(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, const nfl_addr_t *remote_addr);

/**
 * Define an incoming tcp connection. Called when an application invokes 'accept' on a listening sock.
 * Parameters local_addr and remote_addr are guaranteed to be of same type, sockaddr_in or sockaddr_in6
 * @param local_addr The local address bound to the sock.
 * @param remote_addr The address of the remote endpoint. This must be initialized by the module in case the connection was successful.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_accept(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, nfl_addr_t *remote_addr);

/**
 * Called when an application attempts to send data on a network sock
 * @param sock The sock on which a send call was issued
 * @param from The sender address of the packet, type sockaddr_in | sockaddr_in6
 * @param to The destination address of the packet, type sockaddr_in | sockaddr_in6
 * @param iov Array of iovec structs containing the outgoing data
 * @param iovlen The amount of iovec structs in the array
 * @return The amount of bytes sent, or a negative value in case of an error
 */
ssize_t nfl_send(const nfl_sock_module_t *sock, const nfl_addr_t *from, const nfl_addr_t *to, struct iovec *iov, size_t iovlen);

/**
 * Called when an application attempts to read data on a network sock, and the current buffer is empty
 * @param sock The sock on which a read call was issued
 * @param bound_addr The address bound to the sock, type sockaddr_in | sockaddr_in6
 * @return Packet which must be allocated and initialized by the network environment, see nfl_alloc_pkt() in module_provided.h
 *               Must remain unaltered if no packet has been received.
 *               For TCP only the iov field needs to be filled in, other fields are ignored.
 */
nfl_pkt *nfl_receive(const nfl_sock_module_t *sock, const nfl_addr_t *bound_addr);

void nfl_end();

//Reasons for dying: blocking, or liveness heuristic.

// Liveness heuristic: actions: ignore or die
// Blocking: actions: block or die.

#endif //NETFUZZLIB_MODULE_API_H
