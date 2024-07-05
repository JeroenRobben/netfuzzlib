#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include "netfuzzlib/api.h"
#include "hooks.h"
#include "native.h"
#include "models.h"
#include "sockets/sockets_util.h"
#include "environment/fd_table.h"

static int liveness_ctr;

void liveness_ctr_inc() {
    liveness_ctr++;
    if (liveness_ctr >= 10) {
        nfl_log_fatal("5 subsequent select/poll/... calls without event, exiting...");
        nfl_end_priv();
    }
}

void liveness_ctr_clear() {
    liveness_ctr = 0;
}

void split_fds_select(int nfds, int *max_fd_syscall, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, fd_set *read_fds_syscall, fd_set *write_fds_syscall,
                      fd_set *except_fds_syscall) {
    FD_ZERO(read_fds_syscall);
    FD_ZERO(write_fds_syscall);
    FD_ZERO(except_fds_syscall);
    bool do_read, do_write, do_except;
    bool is_set;
    int max_fd = 0;

    for (int i = 0; i < nfds; i++) {
        if (is_nfl_sock_fd(i))
            continue;

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
        if (is_set)
            max_fd = i + 1;
    }
    *max_fd_syscall = max_fd;
}

void merge_fds_select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, fd_set *read_fds_syscall, fd_set *write_fds_syscall,
                      fd_set *except_fds_syscall) {
    for (int i = 0; i < nfds; i++) {
        if (is_nfl_sock_fd(i))
            continue;

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
    assert(nfds <= FD_SETSIZE);

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
    int ret_model = select_nfl(nfds, readfds, writefds, exceptfds);
    if (ret_model < 0) {
        return -1;
    }
    merge_fds_select(nfds, readfds, writefds, exceptfds, &read_fds_syscall, &write_fds_syscall, &except_fds_syscall);

    int ret_total = ret_model + ret_syscall;

    if (ret_total == 0) {
        liveness_ctr_inc();
    } else {
        liveness_ctr_clear();
    }
    return ret_total;
}

int pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    struct timeval my_timeval;
    my_timeval.tv_sec = timeout->tv_sec;
    my_timeval.tv_usec = timeout->tv_nsec / 1000;

    sigset_t origmask;
    pthread_sigmask(SIG_SETMASK, sigmask, &origmask);
    int ready = select(nfds, readfds, writefds, exceptfds, &my_timeval);
    pthread_sigmask(SIG_SETMASK, &origmask, NULL);
    return ready;
}

int poll(struct pollfd *fds, nfds_t nfds, int timeout) {
    if (nfds == 0)
        return 0;

    struct pollfd *fds_syscall = calloc(sizeof(struct pollfd), nfds);
    struct pollfd *fds_model = calloc(sizeof(struct pollfd), nfds);
    if (!fds_syscall || !fds_model) {
        if (fds_syscall)
            free(fds_syscall);
        errno = ENOBUFS;
        return -1;
    }
    int i_fds_syscall = 0;
    int i_fds_model = 0;

    // Split fds into modelled and native fds
    for (int i_fds = 0; i_fds < nfds; i_fds++) {
        struct pollfd *current_poll_struct = &fds[i_fds];
        current_poll_struct->revents = 0;

        if (is_nfl_sock_fd(current_poll_struct->fd)) {
            nfl_log_debug("Modelled (p)poll call for fd: %s", sock_to_str(get_nfl_sock(fds[i_fds].fd)));
            fds_model[i_fds_model].fd = current_poll_struct->fd;
            fds_model[i_fds_model].events = current_poll_struct->events;
            i_fds_model++;
        } else {
            nfl_log_debug("Native (p)poll call for fd: %d", fds[i_fds].fd);
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
    int ret_model = poll_nfl(fds_model, i_fds_model, 0);
    if (ret_model == -1) {
        free(fds_syscall);
        free(fds_model);
        return -1;
    }
    int ret_total = ret_native + ret_model;
    if (ret_total) {
        i_fds_syscall = 0;
        i_fds_model = 0;
        for (int i_fds = 0; i_fds < nfds; i_fds++) {
            fds[i_fds].revents = 0;
            if (is_nfl_sock_fd(fds[i_fds].fd)) {
                fds[i_fds].revents = fds_model[i_fds_model].revents;
                i_fds_model++;
            } else {
                fds[i_fds].revents = fds_syscall[i_fds_syscall].revents;
                i_fds_syscall++;
            }
        }
    }

    free(fds_syscall);
    free(fds_model);

    if (ret_total == 0) {
        liveness_ctr_inc();
    } else {
        liveness_ctr_clear();
    }

    return ret_total;
}

int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    sigset_t origmask;

    int timeout = (timeout_ts == NULL) ? -1 : (int)(timeout_ts->tv_sec * 1000 + timeout_ts->tv_nsec / 1000000);
    sigprocmask(SIG_SETMASK, sigmask, &origmask);
    int ready = poll(fds, nfds, timeout);
    sigprocmask(SIG_SETMASK, &origmask, NULL);
    return ready;
}