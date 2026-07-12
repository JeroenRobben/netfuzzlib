#include "interceptors.h"
#include "core/epoll.h"
#include "core/recv_buffer.h"
#include <assert.h>
#include <netfuzzlib/api.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/epoll.h>

#include "callback_wrapper.h"
#include "native.h"

static void split_fds_select(int nfds, int *max_fd_syscall, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, fd_set *read_fds_syscall, fd_set *write_fds_syscall,
                             fd_set *except_fds_syscall) {
    FD_ZERO(read_fds_syscall);
    FD_ZERO(write_fds_syscall);
    FD_ZERO(except_fds_syscall);
    bool do_read;
    bool do_write;
    bool do_except;
    bool is_set;
    int max_fd = 0;

    for (int i = 0; i < nfds; i++) {
        if (is_nfl_sock_fd(i)) {
            continue;
        }

        do_read = (readfds != NULL) && FD_ISSET(i, readfds);
        do_write = (writefds != NULL) && FD_ISSET(i, writefds);
        do_except = (exceptfds != NULL) && FD_ISSET(i, exceptfds);

        is_set = false;
        if (do_read) {
            is_set = true;
            FD_SET(i, read_fds_syscall);
            FD_CLR(i, readfds);
        }
        if (do_write) {
            is_set = true;
            FD_SET(i, write_fds_syscall);
            FD_CLR(i, writefds);
        }
        if (do_except) {
            is_set = true;
            FD_SET(i, except_fds_syscall);
            FD_CLR(i, exceptfds);
        }
        if (is_set) {
            max_fd = i + 1;
        }
    }
    *max_fd_syscall = max_fd;
}

static void merge_fds_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const fd_set *read_fds_syscall, const fd_set *write_fds_syscall,
                             const fd_set *except_fds_syscall) {
    for (int i = 0; i < nfds; i++) {
        if (is_nfl_sock_fd(i)) {
            continue;
        }

        if (readfds != NULL && FD_ISSET(i, read_fds_syscall)) {
            FD_SET(i, readfds);
        }
        if (writefds != NULL && FD_ISSET(i, write_fds_syscall)) {
            FD_SET(i, writefds);
        }
        if (exceptfds != NULL && FD_ISSET(i, except_fds_syscall)) {
            FD_SET(i, exceptfds);
        }
    }
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    /* NULL timeout is infinite, {0,0} is a poll; any other value is a timed (blocking) wait. */
    const bool blocking = (timeout == NULL) || (timeout->tv_sec != 0) || (timeout->tv_usec != 0);
    assert(nfds <= FD_SETSIZE);

    /* select() fails outright on a closed fd rather than reporting it per-fd. */
    for (int i = 0; i < nfds; i++) {
        if (!nfl_fd_is_closed_placeholder(i)) {
            continue;
        }
        if ((readfds && FD_ISSET(i, readfds)) || (writefds && FD_ISSET(i, writefds)) || (exceptfds && FD_ISSET(i, exceptfds))) {
            errno = EBADF;
            return -1;
        }
    }

    fd_set read_fds_syscall;
    fd_set write_fds_syscall;
    fd_set except_fds_syscall;

    int max_fd_syscall = 0;
    split_fds_select(nfds, &max_fd_syscall, readfds, writefds, exceptfds, &read_fds_syscall, &write_fds_syscall, &except_fds_syscall);
    struct timeval my_timeval = { 0 };
    int ret_syscall = select_native(max_fd_syscall, readfds ? &read_fds_syscall : NULL, writefds ? &write_fds_syscall : NULL,
                                    exceptfds ? &except_fds_syscall : NULL, &my_timeval);

    if (ret_syscall < 0) {
        return ret_syscall;
    }
    my_timeval.tv_sec = 0;
    my_timeval.tv_usec = 0;
    int ret_model = select_nfl(nfds, readfds, writefds, exceptfds, blocking);
    if (ret_model < 0) {
        return -1;
    }
    merge_fds_select(nfds, readfds, writefds, exceptfds, &read_fds_syscall, &write_fds_syscall, &except_fds_syscall);

    int ret_total = ret_model + ret_syscall;
    return ret_total;
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    struct timeval my_timeval;
    struct timeval *timeout_arg = NULL;
    if (timeout) {
        my_timeval.tv_sec = timeout->tv_sec;
        my_timeval.tv_usec = timeout->tv_nsec / 1000;
        timeout_arg = &my_timeval;
    }

    sigset_t origmask;
    sigprocmask(SIG_SETMASK, sigmask, &origmask);
    int ready = select(nfds, readfds, writefds, exceptfds, timeout_arg);
    sigprocmask(SIG_SETMASK, &origmask, NULL);
    return ready;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (nfds == 0) {
        return 0;
    }

    struct pollfd *fds_syscall = calloc(sizeof(struct pollfd), nfds);
    struct pollfd *fds_model = calloc(sizeof(struct pollfd), nfds);
    if (!fds_syscall || !fds_model) {
        free(fds_syscall);
        free(fds_model);
        errno = ENOBUFS;
        return -1;
    }
    int i_fds_syscall = 0;
    int i_fds_model = 0;
    int n_invalid = 0;

    // Split fds into modelled and native fds
    for (int i_fds = 0; i_fds < nfds; i_fds++) {
        struct pollfd *current_poll_struct = &fds[i_fds];
        current_poll_struct->revents = 0;

        if (is_nfl_sock_fd(current_poll_struct->fd)) {
            nfl_log("Modelled (p)poll call for fd: %s", sock_to_str(get_nfl_sock(fds[i_fds].fd)));
            fds_model[i_fds_model].fd = current_poll_struct->fd;
            fds_model[i_fds_model].events = current_poll_struct->events;
            i_fds_model++;
        } else if (nfl_fd_is_closed_placeholder(current_poll_struct->fd)) {
            /* Polling the placeholder natively would find a readable /dev/null. */
            n_invalid++;
        } else {
            nfl_log("Native (p)poll call for fd: %d", fds[i_fds].fd);
            fds_syscall[i_fds_syscall].fd = current_poll_struct->fd;
            fds_syscall[i_fds_syscall].events = current_poll_struct->events;
            i_fds_syscall++;
        }
    }
    int ret_native = poll_native(fds_syscall, i_fds_syscall, 0);
    if (ret_native == -1) {
        free(fds_syscall);
        free(fds_model);
        return -1;
    }
    int ret_model = poll_nfl(fds_model, i_fds_model, timeout);
    if (ret_model == -1) {
        free(fds_syscall);
        free(fds_model);
        return -1;
    }
    int ret_total = ret_native + ret_model + n_invalid;
    if (ret_total) {
        i_fds_syscall = 0;
        i_fds_model = 0;
        for (int i_fds = 0; i_fds < nfds; i_fds++) {
            fds[i_fds].revents = 0;
            if (is_nfl_sock_fd(fds[i_fds].fd)) {
                fds[i_fds].revents = fds_model[i_fds_model].revents;
                i_fds_model++;
            } else if (nfl_fd_is_closed_placeholder(fds[i_fds].fd)) {
                fds[i_fds].revents = POLLNVAL;
            } else {
                fds[i_fds].revents = fds_syscall[i_fds_syscall].revents;
                i_fds_syscall++;
            }
        }
    }

    free(fds_syscall);
    free(fds_model);

    return ret_total;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    sigset_t origmask;

    int timeout = (timeout_ts == NULL) ? -1 : (int)((timeout_ts->tv_sec * 1000) + (timeout_ts->tv_nsec / 1000000));
    sigprocmask(SIG_SETMASK, sigmask, &origmask);
    int ready = poll(fds, nfds, timeout);
    sigprocmask(SIG_SETMASK, &origmask, NULL);
    return ready;
}

/* glibc fortify wrappers. See comment in interceptors.c. */
int __poll_chk(struct pollfd *fds, nfds_t nfds, int timeout, size_t fdslen) {
    (void)fdslen;
    return poll(fds, nfds, timeout);
}

int __ppoll_chk(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts,
                const sigset_t *sigmask, size_t fdslen) {
    (void)fdslen;
    return ppoll(fds, nfds, timeout_ts, sigmask);
}

/* epoll family. Fall through to native if the epoll fd isn't ours, or if the
 * call is on an nfl-fd targeting native epoll. We only handle nfl-epoll +
 * nfl-watched-fd combinations, everything else passes through. */
int epoll_create(int size) {
    return epoll_create_nfl(size);
}

int epoll_create1(int flags) {
    return epoll_create1_nfl(flags);
}

int epoll_ctl(int epfd, int op, int fd, struct epoll_event *event) {
    nfl_sock_full_t *epoll_sock = get_nfl_sock(epfd);
    if (epoll_sock && epoll_sock->epoll_data) {
        return epoll_ctl_nfl(epoll_sock, op, fd, event);
    }
    if (epoll_sock) {
        /* epfd is an nfl socket but not an epoll instance. */
        errno = EINVAL;
        return -1;
    }
    return epoll_ctl_native(epfd, op, fd, event);
}

int epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout) {
    nfl_sock_full_t *epoll_sock = get_nfl_sock(epfd);
    if (epoll_sock && epoll_sock->epoll_data) {
        return epoll_wait_nfl(epoll_sock, events, maxevents, timeout);
    }
    if (epoll_sock) {
        errno = EINVAL;
        return -1;
    }
    return epoll_wait_native(epfd, events, maxevents, timeout);
}

int epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout,
                const sigset_t *sigmask) {
    nfl_sock_full_t *epoll_sock = get_nfl_sock(epfd);
    if (epoll_sock && epoll_sock->epoll_data) {
        return epoll_pwait_nfl(epoll_sock, events, maxevents, timeout, sigmask);
    }
    if (epoll_sock) {
        errno = EINVAL;
        return -1;
    }
    return epoll_pwait_native(epfd, events, maxevents, timeout, sigmask);
}

int epoll_pwait2(int epfd, struct epoll_event *events, int maxevents,
                 const struct timespec *timeout, const sigset_t *sigmask) {
    nfl_sock_full_t *epoll_sock = get_nfl_sock(epfd);
    if (epoll_sock && epoll_sock->epoll_data) {
        return epoll_pwait2_nfl(epoll_sock, events, maxevents, timeout, sigmask);
    }
    if (epoll_sock) {
        errno = EINVAL;
        return -1;
    }
    return epoll_pwait2_native(epfd, events, maxevents, timeout, sigmask);
}
