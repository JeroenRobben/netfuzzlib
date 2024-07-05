#ifndef NETFUZZLIB_HOOKS_H
#define NETFUZZLIB_HOOKS_H

#include "models.h"
#include "native.h"
#include "environment/fd_table.h"
#include <stdlib.h>
#include <errno.h>

#define SWITCH_MODEL_NATIVE(fd, userspace_func, native_func, args...)               \
    do {                                                                            \
        nfl_sock_t *sock = get_nfl_sock(fd);                                        \
        if (sock) {                                                                 \
            errno = 0;                                                              \
            return userspace_func(sock, args);                                      \
        } else {                                                                    \
            nfl_log_debug("Forwarding %s() to %s", __func__, native_fd_to_str(fd)); \
            return native_func(fd, args);                                           \
        }                                                                           \
    } while (0)

#define SWITCH_MODEL_NATIVE_STREAM(stream, userspace_func, native_func, args...) \
    do {                                                                         \
        int fd = fileno(stream);                                                 \
        if (stream_is_casted_fd(stream) || is_nfl_sock_fd((fd))) {               \
            errno = 0;                                                           \
            nfl_sock_t *sock = get_nfl_sock(fd);                                 \
            return userspace_func(args, sock);                                   \
        } else {                                                                 \
            return native_func(args, stream);                                    \
        }                                                                        \
    } while (0)

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

void liveness_ctr_clear();
void nfl_end_priv();
char *native_fd_to_str(int fd);

bool stream_is_casted_fd(FILE *stream);

/**
 * Return whether a combination of domain, type and protocol is supported by netfuzzlib.
 * @param domain The domain to check, e.g., AF_INET
 * @param type The socket type to check, e.g., SOCK_STREAM
 * @param protocol The socket protocol to check, e.g., IPPROTO_TCP
 * @return True iff the given combination of domain, type and protocol is supported by netfuzzlib.
 */
bool is_socket_supported(int domain, int type, int protocol);

#endif // NETFUZZLIB_HOOKS_H
