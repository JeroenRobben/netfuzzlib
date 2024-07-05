#include <stdlib.h>
#include <errno.h>
#include <netfuzzlib/log.h>
#include "hooks/models.h"
#include "environment/network_env.h"
#include "hooks/native.h"
#include "environment/fd_table.h"

int dup_nfl_fd(int oldfd) {
    nfl_sock_t *sock_oldfd = get_nfl_sock(oldfd);
    if (!sock_oldfd) {
        errno = EBADF;
        return -1;
    }
    return dup_nfl_sock(sock_oldfd);
}

int dup_nfl_sock(nfl_sock_t *old_sock) {
    int newfd = get_available_fd();
    if (newfd < 0) {
        errno = EMFILE;
        return -1;
    }
    fd_table_set(newfd, old_sock);
    return newfd;
}

int dup2_nfl(int oldfd, int newfd) {
    if (oldfd == newfd || !is_nfl_sock_fd(oldfd) || newfd < 0) {
        errno = EINVAL;
        return -1;
    }
    if (newfd >= SOCKET_FD_MAX) {
        nfl_exit_log(1, "dup2_nfl: newfd >= SOCKET_FD_MAX");
    }
    nfl_sock_t *sock_oldfd = get_nfl_sock(oldfd);
    if (get_nfl_sock(newfd)) {
        close_nfl_fd(newfd);
    }
    fd_table_set(newfd, sock_oldfd);
    dup2_native(get_network_env()->fd_dev_null,
                newfd); //Reserve the new fd;
    return newfd;
}

int dup3_nfl(int oldfd, int newfd, int flags) {
    return dup2_nfl(oldfd, newfd);
}