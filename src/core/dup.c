#include <errno.h>
#include <fcntl.h>
#include <netfuzzlib/log.h>
#include "network_env.h"
#include "interceptors/native.h"
#include "handlers.h"
#include "fd_table.h"

int dup_nfl_fd(int oldfd) {
    nfl_sock_full_t *sock_oldfd = get_nfl_sock(oldfd);
    if (!sock_oldfd) {
        errno = EBADF;
        return -1;
    }
    return dup_nfl_sock(sock_oldfd);
}

int dup_nfl_sock(nfl_sock_full_t *old_sock) {
    const int newfd = get_available_fd();
    if (newfd < 0) {
        errno = EMFILE;
        return -1;
    }
    fd_table_set(newfd, old_sock);
    return newfd;
}

int dup2_nfl(int oldfd, int newfd) {
    if (!is_nfl_sock_fd(oldfd) || newfd < 0) {
        errno = EBADF;
        return -1;
    }
    // POSIX: dup2(fd, fd) is a no-op when fd is valid.
    if (oldfd == newfd) {
        return newfd;
    }
    if (newfd >= NFL_FD_TABLE_SIZE) {
        errno = EBADF;
        return -1;
    }
    nfl_sock_full_t *sock_oldfd = get_nfl_sock(oldfd);
    if (get_nfl_sock(newfd)) {
        close_nfl_fd(newfd);
    }
    fd_table_set(newfd, sock_oldfd);
    /* A pool fd is already held open on /dev/null. Any other number is the
     * SUT's, so take it over and reserve it the same way. */
    if (!nfl_fd_is_pool(newfd)) {
        dup2_native(get_network_env()->fd_dev_null, newfd);
    }
    return newfd;
}

int dup3_nfl(int oldfd, int newfd, int flags) {
    // POSIX: dup3 must reject any flag other than O_CLOEXEC.
    if ((flags & ~O_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }
    // dup3(fd, fd, ...) is required to fail with EINVAL (unlike dup2).
    if (oldfd == newfd) {
        errno = EINVAL;
        return -1;
    }
    return dup2_nfl(oldfd, newfd);
}