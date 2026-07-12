#ifndef NETFUZZLIB_INTERCEPTORS_H
#define NETFUZZLIB_INTERCEPTORS_H

#include "core/fd_table.h"
#include "core/handlers.h"
#include <stdbool.h>
#include <errno.h>
#include <stdio.h>

#define SWITCH_MODEL_NATIVE(fd, userspace_func, native_func, args...)            \
    do {                                                                         \
        nfl_sock_full_t *sock = get_nfl_sock(fd);                                     \
        if (sock) {                                                              \
            if (sock->kind == NFL_FD_EPOLL) {                                    \
                /* Socket I/O on an epoll fd: like real Linux, return EINVAL. */ \
                errno = EINVAL;                                                  \
                return -1;                                                       \
            }                                                                    \
            errno = 0;                                                           \
            return userspace_func(sock, args);                                   \
        }                                                                        \
        if (nfl_fd_is_closed_placeholder(fd)) {                                  \
            /* Never let the call reach the /dev/null behind the placeholder. */ \
            errno = EBADF;                                                       \
            return -1;                                                           \
        }                                                                        \
        nfl_log("Forwarding %s() to %s", __func__, native_fd_to_str(fd));  \
        return native_func(fd, args);                                            \
    } while (0)

#define SWITCH_MODEL_NATIVE_STREAM(stream, userspace_func, native_func, args...) \
    do {                                                                         \
        int fd = fileno(stream);                                                 \
        if (is_nfl_sock_stream(stream)) {                                        \
            errno = 0;                                                           \
            nfl_sock_full_t *sock = get_nfl_sock(fd);                                 \
            return userspace_func(args, sock);                                   \
        }                                                                        \
        return native_func(args, stream);                                        \
    } while (0)

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

char *native_fd_to_str(int fd);
bool is_nfl_sock_stream(FILE *stream);

/**
 * Return whether a combination of domain, type and protocol is supported by netfuzzlib.
 * @param domain The domain to check, e.g., AF_INET
 * @param type The socket type to check, e.g., SOCK_STREAM
 * @param protocol The socket protocol to check, e.g., IPPROTO_TCP
 * @return True if the given combination of domain, type and protocol is supported by netfuzzlib.
 */
bool is_socket_supported(int domain, int type, int protocol);

#endif // NETFUZZLIB_INTERCEPTORS_H
