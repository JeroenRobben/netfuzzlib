#ifndef NETFUZZLIB_FD_TABLE_H
#define NETFUZZLIB_FD_TABLE_H

#include "network_types.h"

/**
 * True if the given file descriptor is an nfl socket file descriptor
 * @param fd    The file descriptor to check
 * @return    True if the given file descriptor is an nfl socket file descriptor
 */
bool is_nfl_sock_fd(int fd);

/**
 * Return the nfl_sock_full_t for a given file descriptor.
 * @param fd   The file descriptor to get the nfl_sock_full_t for
 * @return The nfl_sock_full_t for the given file descriptor,
 * or NULL if the file descriptor does not belong to a netfuzzlib socket.
 */
nfl_sock_full_t *get_nfl_sock(int fd);

/**
 * Allocate space for a new nfl_sock_full_t and add it to the network environment.
 * It is up to the caller to configure all parameters.
 * @return the fd of the new allocated socket.
 */
int alloc_nfl_sock();

/**
 * Free a socket.
 * @param sock The socket to free
 */
void free_nfl_sock(nfl_sock_full_t *sock);

/**
 * Return the next available file descriptor.
 * Returns -1 if no file descriptors are available.
 */
int get_available_fd();

/**
 * Return the lowest available file descriptor >= min_fd, or -1 if none.
 */
int get_available_fd_from(int min_fd);

/**
 * True if this fd number is one netfuzzlib claimed from the kernel to hand out
 * for modelled sockets. Such a number is held open on /dev/null, so it is never
 * handed to the SUT by open()/pipe()/etc, and must never be closed: releasing it
 * would let the kernel alias a real file onto a modelled socket. Numbers are
 * claimed lazily (or up front via nfl_reserve_fd_pool). True whether or not a
 * socket currently occupies it.
 */
bool nfl_fd_is_pool(int fd);

/**
 * True if this fd is a reserved number with no modelled socket in it: closed
 * from the SUT's point of view, even though it is still open on /dev/null. Every
 * intercepted call on such an fd must fail as it would on a closed one, rather
 * than reaching the placeholder.
 */
bool nfl_fd_is_closed_placeholder(int fd);

/**
 *  Set the given file descriptor to the given socket.
 * @param fd  The file descriptor to set
 * @param sock  The socket to set
 */
void fd_table_set(int fd, nfl_sock_full_t *sock);

/**
 * Clear the given file descriptor from the file descriptor table.
 * @param fd  The file descriptor to clear
 */
void fd_table_clear(int fd);

/* Interceptor-facing close entry points (impls in fd_table.c). */
int close_nfl_fd(int fd);
int close_range_nfl(unsigned int low_fd, unsigned int max_fd);

#endif // NETFUZZLIB_FD_TABLE_H
