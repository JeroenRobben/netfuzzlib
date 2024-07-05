#ifndef NETFUZZLIB_FD_TABLE_H
#define NETFUZZLIB_FD_TABLE_H

#include "sockets/network_types.h"

/**
 * True iff the given file descriptor is a socket file descriptor
 * @param fd    The file descriptor to check
 * @return    True iff the given file descriptor is a socket file descriptor
 */
bool is_nfl_sock_fd(int fd);

/**
 * Return the nfl_sock_t for a given file descriptor.
 * @param fd   The file descriptor to get the nfl_sock_t for
 * @return The nfl_sock_t for the given file descriptor,
 * or NULL if the file descriptor does not belong to a netfuzzlib socket.
 */
nfl_sock_t *get_nfl_sock(int fd);

/**
 * Allocate space for a new nfl_sock_t and add it to the network environment.
 * It is up to the caller to configure all parameters. sock->references is set to 1
 * @return the fd of the new allocated socket.
 */
int alloc_nfl_sock();

/**
 * Free a socket.
 * @param sock The socket to free
 */
void free_nfl_sock(nfl_sock_t *sock);

/**
 * Return the next available file descriptor.
 * Returns -1 if no file descriptors are available.
 */
int get_available_fd();

/**
 *  Set the given file descriptor to the given socket.
 * @param fd  The file descriptor to set
 * @param sock  The socket to set
 */
void fd_table_set(int fd, nfl_sock_t *sock);

/**
 * Clear the given file descriptor from the file descriptor table.
 * @param fd  The file descriptor to clear
 */
void fd_table_clear(int fd);

#endif //NETFUZZLIB_FD_TABLE_H
