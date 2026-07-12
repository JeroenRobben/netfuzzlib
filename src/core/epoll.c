#include "epoll.h"

#include "fd_table.h"
#include "callback_wrapper.h"
#include "interceptors/native.h"
#include "handlers.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netfuzzlib/api.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>

static const uint32_t kReadinessMask = EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

enum { NFL_EPOLL_MAX_DEPTH = 5 };

static void watch_link_to_target(nfl_epoll_watch_t *watch) {
    watch->prev = NULL;
    watch->next = watch->target->watch_list;
    if (watch->next) {
        watch->next->prev = watch;
    }
    watch->target->watch_list = watch;
}

static void watch_unlink_from_target(nfl_epoll_watch_t *watch) {
    if (watch->prev) {
        watch->prev->next = watch->next;
    } else {
        watch->target->watch_list = watch->next;
    }
    if (watch->next) {
        watch->next->prev = watch->prev;
    }
    watch->prev = NULL;
    watch->next = NULL;
}

static void watch_unlink_from_owner(nfl_epoll_watch_t *watch) {
    nfl_epoll_t *ep = watch->owner;
    for (size_t i = 0; i < ep->n_watches; i++) {
        if (ep->watches[i] != watch) {
            continue;
        }
        ep->watches[i] = ep->watches[ep->n_watches - 1];
        ep->n_watches--;
        if (ep->rr_cursor >= ep->n_watches) {
            ep->rr_cursor = 0;
        }
        return;
    }
}

static void watch_destroy(nfl_epoll_watch_t *watch) {
    watch_unlink_from_owner(watch);
    watch_unlink_from_target(watch);
    free(watch);
}

void epoll_detach_watches_on(nfl_sock_full_t *sock) {
    while (sock->watch_list) {
        watch_destroy(sock->watch_list);
    }
}

static nfl_epoll_watch_t *epoll_find(const nfl_epoll_t *ep, const int fd) {
    for (size_t i = 0; i < ep->n_watches; i++) {
        if (ep->watches[i]->fd == fd) {
            return ep->watches[i];
        }
    }
    return NULL;
}

static int epoll_grow(nfl_epoll_t *ep) {
    const size_t newcap = ep->cap ? ep->cap * 2 : 4;
    nfl_epoll_watch_t **p = realloc(ep->watches, newcap * sizeof(*p));
    if (!p) {
        errno = ENOMEM;
        return -1;
    }
    ep->watches = p;
    ep->cap = newcap;
    return 0;
}

static int alloc_shadow_epfd(const int flags) {
    const int fd = epoll_create1_native(flags);
    if (fd < 0) {
        return -1;
    }
    const int cmd = (flags & EPOLL_CLOEXEC) ? F_DUPFD_CLOEXEC : F_DUPFD;
    const int reserved = fcntl_native(fd, cmd, NFL_RESERVED_FD_MODULE_START);
    if (reserved < 0) {
        return fd;
    }
    close_native(fd);
    return reserved;
}

static int alloc_epoll_fd(const int flags) {
    if ((flags & ~EPOLL_CLOEXEC) != 0) {
        errno = EINVAL;
        return -1;
    }
    const int fd = alloc_nfl_sock();
    if (fd < 0) {
        errno = EMFILE;
        return -1;
    }
    nfl_sock_full_t *sock = get_nfl_sock(fd);
    sock->kind = NFL_FD_EPOLL;
    sock->domain = -1;
    sock->type = -1;
    sock->protocol = -1;
    sock->epoll_data = calloc(1, sizeof(nfl_epoll_t));
    if (!sock->epoll_data) {
        close_nfl_fd(fd);
        errno = ENOMEM;
        return -1;
    }
    sock->epoll_data->native_epfd = -1;
    sock->epoll_data->create_flags = flags;
    return fd;
}

int epoll_create_nfl(const int size) {
    if (size <= 0) {
        errno = EINVAL;
        return -1;
    }
    return alloc_epoll_fd(0);
}

int epoll_create1_nfl(const int flags) {
    return alloc_epoll_fd(flags);
}

void epoll_free(nfl_epoll_t *ep) {
    if (!ep) {
        return;
    }
    while (ep->n_watches > 0) {
        watch_destroy(ep->watches[ep->n_watches - 1]);
    }
    if (ep->native_epfd >= 0) {
        close_native(ep->native_epfd);
    }
    free(ep->watches);
    free(ep);
}

static bool epoll_reaches(const nfl_sock_full_t *from, const nfl_sock_full_t *goal, const int depth) {
    if (from == goal) {
        return true;
    }
    if (from->kind != NFL_FD_EPOLL || depth > NFL_EPOLL_MAX_DEPTH) {
        return false;
    }
    const nfl_epoll_t *ep = from->epoll_data;
    for (size_t i = 0; i < ep->n_watches; i++) {
        if (epoll_reaches(ep->watches[i]->target, goal, depth + 1)) {
            return true;
        }
    }
    return false;
}

static int epoll_nesting_depth(const nfl_sock_full_t *node, const int depth) {
    if (node->kind != NFL_FD_EPOLL || depth > NFL_EPOLL_MAX_DEPTH) {
        return 0;
    }
    const nfl_epoll_t *ep = node->epoll_data;
    int deepest = 0;
    for (size_t i = 0; i < ep->n_watches; i++) {
        const int d = epoll_nesting_depth(ep->watches[i]->target, depth + 1);
        if (d > deepest) {
            deepest = d;
        }
    }
    return deepest + 1;
}

static int epoll_check_nesting(const nfl_sock_full_t *epoll_sock, const nfl_sock_full_t *target) {
    if (target->kind != NFL_FD_EPOLL) {
        return 0;
    }
    if (epoll_reaches(target, epoll_sock, 0)) {
        errno = ELOOP;
        return -1;
    }
    if (epoll_nesting_depth(target, 0) + 1 > NFL_EPOLL_MAX_DEPTH) {
        errno = EINVAL;
        return -1;
    }
    return 0;
}

static void watch_arm(nfl_epoll_watch_t *watch, const struct epoll_event *event) {
    watch->events = event->events;
    watch->data = event->data.u64;
    watch->disarmed = false;
    watch->last_revents = 0;
    watch->last_seq = watch->target->ready_seq;
}

static int epoll_ctl_native_fd(nfl_epoll_t *ep, const int op, const int fd, struct epoll_event *event) {
    if (ep->native_epfd < 0) {
        if (op != EPOLL_CTL_ADD) {
            errno = ENOENT;
            return -1;
        }
        ep->native_epfd = alloc_shadow_epfd(ep->create_flags);
        if (ep->native_epfd < 0) {
            return -1;
        }
    }
    const int rc = epoll_ctl_native(ep->native_epfd, op, fd, event);
    if (rc != 0) {
        return rc;
    }
  if (op == EPOLL_CTL_ADD) {
        ep->n_native_watches++;
    } else if (op == EPOLL_CTL_DEL && ep->n_native_watches > 0) {
        ep->n_native_watches--;
    }
    return 0;
}

int epoll_ctl_nfl(nfl_sock_full_t *epoll_sock, const int op, const int fd, struct epoll_event *event) {
    nfl_epoll_t *ep = epoll_sock->epoll_data;
    if (!ep) {
        errno = EINVAL;
        return -1;
    }
    if (op != EPOLL_CTL_DEL && !event) {
        errno = EFAULT;
        return -1;
    }
    nfl_sock_full_t *target = get_nfl_sock(fd);
    if (target == epoll_sock) {
        errno = EINVAL;
        return -1;
    }
    if (!target) {
        if (nfl_fd_is_closed_placeholder(fd)) {
            errno = EBADF;
            return -1;
        }
        return epoll_ctl_native_fd(ep, op, fd, event);
    }

    nfl_epoll_watch_t *existing = epoll_find(ep, fd);
    switch (op) {
    case EPOLL_CTL_ADD: {
        if (existing) {
            errno = EEXIST;
            return -1;
        }
        if (epoll_check_nesting(epoll_sock, target) != 0) {
            return -1;
        }
        if (ep->n_watches == ep->cap && epoll_grow(ep) != 0) {
            return -1;
        }
        nfl_epoll_watch_t *watch = calloc(1, sizeof(*watch));
        if (!watch) {
            errno = ENOMEM;
            return -1;
        }
        watch->owner = ep;
        watch->target = target;
        watch->fd = fd;
        watch_arm(watch, event);
        watch_link_to_target(watch);
        ep->watches[ep->n_watches++] = watch;
        return 0;
    }
    case EPOLL_CTL_MOD:
        if (!existing) {
            errno = ENOENT;
            return -1;
        }
        watch_arm(existing, event);
        return 0;
    case EPOLL_CTL_DEL:
        if (!existing) {
            errno = ENOENT;
            return -1;
        }
        watch_destroy(existing);
        return 0;
    default:
        errno = EINVAL;
        return -1;
    }
}

static int epoll_drain_native(nfl_epoll_t *ep, struct epoll_event *events, const int cap) {
    if (cap <= 0 || ep->n_native_watches == 0 || ep->native_epfd < 0) {
        return 0;
    }
    return epoll_wait_native(ep->native_epfd, events, cap, 0);
}

static bool watch_should_report(nfl_epoll_watch_t *watch, const uint32_t revents) {
    if (!(watch->events & EPOLLET)) {
        return true;
    }
    const bool edge = (revents & ~watch->last_revents) != 0 || watch->last_seq != watch->target->ready_seq;
    watch->last_revents = revents;
    watch->last_seq = watch->target->ready_seq;
    return edge;
}

static int epoll_drain_nfl(nfl_epoll_t *ep, struct epoll_event *events, const int cap, const bool blocking) {
    if (cap <= 0 || ep->n_watches == 0) {
        return 0;
    }
    const size_t n = ep->n_watches;
    const size_t start = ep->rr_cursor % n;
    int out = 0;

    for (size_t k = 0; k < n && out < cap; k++) {
        const size_t i = (start + k) % n;
        nfl_epoll_watch_t *watch = ep->watches[i];
        if (watch->disarmed) {
            continue;
        }
        const uint32_t interest = watch->events & kReadinessMask;
        const uint32_t revents = sock_poll_with_gap(watch->target, interest, blocking) & (interest | EPOLLERR | EPOLLHUP);
        if (!revents) {
            watch->last_revents = 0;
            watch->last_seq = watch->target->ready_seq;
            continue;
        }
        if (!watch_should_report(watch, revents)) {
            continue;
        }
        events[out].events = revents;
        events[out].data.u64 = watch->data;
        out++;
        if (watch->events & EPOLLONESHOT) {
            watch->disarmed = true;
        }
        ep->rr_cursor = (i + 1) % n;
    }
    return out;
}

static int epoll_collect(nfl_epoll_t *ep, struct epoll_event *events, const int maxevents, const bool blocking) {
    const bool have_nfl = ep->n_watches > 0;
    const bool have_native = ep->n_native_watches > 0 && ep->native_epfd >= 0;
    if (!have_nfl && !have_native) {
        return 0;
    }

    int lead_cap = maxevents;
    if (have_nfl && have_native) {
        lead_cap = (maxevents + 1) / 2;
        ep->rr_native_first = !ep->rr_native_first;
    }

    int out;
    if (ep->rr_native_first) {
        const int n_native = epoll_drain_native(ep, events, lead_cap);
        if (n_native < 0) {
            return -1;
        }
        out = n_native + epoll_drain_nfl(ep, events + n_native, maxevents - n_native, blocking);
    } else {
        out = epoll_drain_nfl(ep, events, lead_cap, blocking);
        const int n_native = epoll_drain_native(ep, events + out, maxevents - out);
        if (n_native < 0) {
            return -1;
        }
        out += n_native;
    }
    return out;
}

static void epoll_liveness_update(nfl_epoll_t *ep, int out) {
    if (out > 0) {
        for (size_t i = 0; i < ep->n_watches; i++) {
            sock_idle_clear(ep->watches[i]->target);
        }
        return;
    }
    // Idle wait: tick each armed nfl watch so its module's nfl_socket_idle is
    // consulted at the threshold. netfuzzlib never exits on its own.
    for (size_t i = 0; i < ep->n_watches; i++) {
        if (!ep->watches[i]->disarmed) {
            sock_idle_tick(ep->watches[i]->target);
        }
    }
}

int epoll_wait_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events, const int maxevents, const int timeout) {
    nfl_epoll_t *ep = epoll_sock->epoll_data;
    if (!ep || maxevents <= 0 || !events) {
        errno = EINVAL;
        return -1;
    }

    const bool blocking = (timeout != 0); // any non-zero (finite or infinite) timeout skips the gap
    const int out = epoll_collect(ep, events, maxevents, blocking);
    if (out < 0) {
        return -1;
    }
    epoll_liveness_update(ep, out);
    return out;
}

int epoll_pwait_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events, const int maxevents, const int timeout, const sigset_t *sigmask) {
    if (!sigmask) {
        return epoll_wait_nfl(epoll_sock, events, maxevents, timeout);
    }
    sigset_t origmask;
    sigprocmask(SIG_SETMASK, sigmask, &origmask);
    const int ret = epoll_wait_nfl(epoll_sock, events, maxevents, timeout);
    const int saved_errno = errno;
    sigprocmask(SIG_SETMASK, &origmask, NULL);
    errno = saved_errno;
    return ret;
}

int epoll_pwait2_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events, const int maxevents, const struct timespec *timeout, const sigset_t *sigmask) {
    int timeout_ms = -1;
    if (timeout) {
        if (timeout->tv_sec < 0 || timeout->tv_nsec < 0 || timeout->tv_nsec >= 1000000000L) {
            errno = EINVAL;
            return -1;
        }
        const long ms = timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000;
        timeout_ms = ms > INT_MAX ? INT_MAX : (int)ms;
    }
    return epoll_pwait_nfl(epoll_sock, events, maxevents, timeout_ms, sigmask);
}
