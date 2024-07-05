#include <stdlib.h>
#include <errno.h>
#include "fd_table.h"
#include "netfuzzlib/api.h"
#include "sockets/network_types.h"
#include "network_env.h"
#include "sockets/sockets_util.h"

void fd_table_set(int fd, nfl_sock_t *sock) {
    if (get_network_env()->fd_table[fd] != sock) {
        sock->references++;
        get_network_env()->fd_table[fd] = sock;
    }
}

void fd_table_clear(int fd) {
    get_network_env()->fd_table[fd] = NULL;
}

void free_nfl_sock(nfl_sock_t *sock) {
    if (sock->local_addr) {
        free(sock->local_addr);
    }

    if (sock->remote_addr) {
        free(sock->remote_addr);
    }

    if (sock->packets_ll) {
        free_packet_ll(sock->packets_ll);
    }
    free(sock);
}

int get_available_fd() {
    for (int i = SOCKET_FD_START; i < SOCKET_FD_MAX; i++) {
        if (!get_network_env()->fd_table[i])
            return i;
    }
    return -1;
}

int alloc_nfl_sock() {
    int fd = get_available_fd();
    if (fd < 0)
        return -1;
    nfl_sock_t *sock = calloc(1, sizeof(nfl_sock_t));
    if (!sock)
        return -1;
    fd_table_set(fd, sock);
    sock->references = 1;
    return fd;
}

bool is_nfl_sock_fd(int fd) {
    return get_nfl_sock(fd) != NULL;
}

nfl_sock_t *get_nfl_sock(int fd) {
    if (fd < 0 || fd > SOCKET_FD_MAX) {
        return NULL;
    }
    return get_network_env()->fd_table[fd];
}

int close_nfl_sock(nfl_sock_t *sock) {
    nfl_log_debug("close() for %s", sock_to_str(sock));
    for (int i = 0; i < SOCKET_FD_MAX; i++) {
        if (get_nfl_sock(i) == sock) {
            fd_table_clear(i);
        }
    }
    free_nfl_sock(sock);
    return 0;
}

int close_nfl_fd(int fd) {
    nfl_sock_t *sock = get_nfl_sock(fd);
    if (!sock) {
        errno = EINVAL;
        return -1;
    }
    nfl_log_debug("close() for %s", sock_to_str(sock));
    sock->references--;
    if (sock->references <= 0) {
        free_nfl_sock(sock);
    }
    fd_table_clear(fd);
    return 0;
}

int close_range_nfl(unsigned int low_fd, unsigned int max_fd, int flags) {
    for (int i = (int)low_fd; i < max_fd && i < SOCKET_FD_MAX; i++) {
        nfl_sock_t *sock = get_nfl_sock(i);
        if (sock) {
            sock->references--;
            if (sock->references <= 0) {
                free_nfl_sock(sock);
            }
            fd_table_clear(i);
        }
    }
    return 0;
}
