#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include "fd_table.h"
#include "callback_wrapper.h"
#include "epoll.h"
#include "network_types.h"
#include "network_env.h"
#include "recv_buffer.h"
#include "interceptors/native.h"
#include <netfuzzlib/api.h>

void fd_table_set(const int fd, nfl_sock_full_t *sock) {
    if (get_network_env()->fd_table[fd] != sock) {
        sock->references++;
        get_network_env()->fd_table[fd] = sock;
    }
}

void fd_table_clear(const int fd) {
    get_network_env()->fd_table[fd] = NULL;
}

void free_nfl_sock(nfl_sock_full_t *sock) {
    epoll_detach_watches_on(sock);

    if (sock->local_addr) {
        free(sock->local_addr);
    }

    if (sock->remote_addr) {
        free(sock->remote_addr);
    }

    if (sock->packets_ll) {
        free_packet_ll(sock->packets_ll);
    }
    if (sock->epoll_data) {
        epoll_free(sock->epoll_data);
    }
    free(sock);
}

static void nfl_sock_unref(nfl_sock_full_t *sock) {
    if (--sock->references > 0) {
        return;
    }
    nfl_sock_close_priv((const nfl_sock_t *)sock);
    free_nfl_sock(sock);
}

bool nfl_fd_is_pool(const int fd) {
    if (fd < 0 || fd >= NFL_FD_TABLE_SIZE) {
        return false;
    }
    return get_network_env()->fd_in_pool[fd];
}

bool nfl_fd_is_closed_placeholder(const int fd) {
    return nfl_fd_is_pool(fd) && !get_network_env()->fd_table[fd];
}

// Claim fd number `fd` for modelled sockets by holding it open on /dev/null, so
// the kernel can never hand it to the SUT's next open()/pipe(). CLOEXEC so a
// fork+exec child starts from a clean table and reserves its own numbers rather
// than inheriting stale placeholders. Returns false if RLIMIT_NOFILE is reached.
static bool reserve_placeholder_fd(const int fd) {
    network_env *env = get_network_env();
    if (dup2_native(env->fd_dev_null, fd) < 0) {
        return false;
    }
    fcntl_native(fd, F_SETFD, FD_CLOEXEC);
    env->fd_in_pool[fd] = true;
    return true;
}

int get_available_fd_from(const int min_fd) {
    const int start = min_fd < SOCKET_FD_START ? SOCKET_FD_START : min_fd;
    for (int fd = start; fd < NFL_FD_TABLE_SIZE; fd++) {
        if (nfl_fd_is_pool(fd)) {
            if (!get_network_env()->fd_table[fd]) {
                return fd; // recycle a reserved-but-free placeholder
            }
            continue; // a live modelled socket already holds this number
        }
        if (fcntl_native(fd, F_GETFD, 0) >= 0) {
            continue; // a real fd the SUT holds, never alias onto it
        }
        if (reserve_placeholder_fd(fd)) {
            return fd; // claimed a free kernel number lazily
        }
        return -1; // could not reserve (RLIMIT_NOFILE)
    }
    return -1;
}

void nfl_reserve_fd_pool(const int count) {
    int reserved = 0;
    for (int fd = SOCKET_FD_START; fd < NFL_FD_TABLE_SIZE && reserved < count; fd++) {
        if (nfl_fd_is_pool(fd)) {
            reserved++; // already reserved, or in use by a modelled socket
            continue;
        }
        if (fcntl_native(fd, F_GETFD, 0) >= 0) {
            continue; // a real fd occupies this number, leave it alone
        }
        if (!reserve_placeholder_fd(fd)) {
            break; // RLIMIT_NOFILE reached
        }
        reserved++;
    }
    nfl_log("Preregistered %d socket file descriptors", reserved);
}

int get_available_fd() {
    return get_available_fd_from(SOCKET_FD_START);
}

int alloc_nfl_sock() {
    const int fd = get_available_fd();
    if (fd < 0) {
        return -1;
    }
    nfl_sock_full_t *sock = calloc(1, sizeof(nfl_sock_full_t));
    if (!sock) {
        return -1;
    }
    fd_table_set(fd, sock);
    sock->references = 1;
    return fd;
}

bool is_nfl_sock_fd(const int fd) {
    return get_nfl_sock(fd) != NULL;
}

nfl_sock_full_t *get_nfl_sock(const int fd) {
    if (fd < 0 || fd >= NFL_FD_TABLE_SIZE) {
        return NULL;
    }
    return get_network_env()->fd_table[fd];
}

int close_nfl_fd(const int fd) {
    nfl_sock_full_t *sock = get_nfl_sock(fd);
    if (!sock) {
        errno = EINVAL;
        return -1;
    }
    nfl_log("close() for %s", sock_to_str(sock));
    fd_table_clear(fd);
    nfl_sock_unref(sock);
    return 0;
}

int close_range_nfl(const unsigned int low_fd, const unsigned int max_fd) {
    const int hi = max_fd >= NFL_FD_TABLE_SIZE ? NFL_FD_TABLE_SIZE - 1 : (int)max_fd;
    for (int i = (int)low_fd; i <= hi; i++) {
        nfl_sock_full_t *sock = get_nfl_sock(i);
        if (sock) {
            fd_table_clear(i);
            nfl_sock_unref(sock);
        }
    }
    return 0;
}
