#include "fd_table.h"
#include "network_env.h"
#include "interceptors/native.h"
#include "handlers.h"
#include "stream.h"
#include "recv_buffer.h"
#include "callback_wrapper.h"
#include <poll.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/select.h>

static int max_idle_polls = 10;

void nfl_set_max_idle_polls(const int n) {
    max_idle_polls = n < 0 ? 0 : n;
}

void sock_idle_clear(nfl_sock_full_t *sock) {
    sock->idle_polls = 0;
}

void sock_idle_tick(nfl_sock_full_t *sock) {
    if (max_idle_polls == 0) {
        return;
    }
    if (++sock->idle_polls < max_idle_polls) {
        return;
    }
    nfl_socket_idle_priv((const nfl_sock_t *)sock);
    sock->idle_polls = 0;
}

static const uint32_t kReadinessMask = EPOLLIN | EPOLLOUT | EPOLLPRI | EPOLLERR | EPOLLHUP | EPOLLRDHUP;

enum { NFL_EPOLL_MAX_DEPTH = 5 };

static uint32_t sock_poll_depth(nfl_sock_full_t *sock, uint32_t interest, int depth);

static uint32_t socket_poll(nfl_sock_full_t *sock, const uint32_t interest) {
    uint32_t revents = 0;

    if (interest & EPOLLIN) {
        if (sock->is_listening) {
            tcp_update_pending_connections(sock);
            if (sock->tcp_pending) {
                revents |= EPOLLIN;
            }
        } else if (sock_recv_buffer_bytes_available(sock) > 0) {
            revents |= EPOLLIN;
        } else if (sock->type == SOCK_STREAM && sock->shutdown_read) {
            revents |= EPOLLIN;
        }
    }
    const bool can_write = !sock->shutdown_write && ((sock->type != SOCK_STREAM) || sock->remote_addr);
    if ((interest & EPOLLOUT) && can_write) {
        revents |= EPOLLOUT;
    }
    if ((interest & EPOLLRDHUP) && sock->type == SOCK_STREAM && sock->shutdown_read) {
        revents |= EPOLLRDHUP;
    }
    if (sock->type == SOCK_STREAM && sock->shutdown_read && sock->shutdown_write) {
        revents |= EPOLLHUP;
    }
    return revents;
}

static bool epoll_instance_ready(nfl_epoll_t *ep, const int depth) {
    if (depth > NFL_EPOLL_MAX_DEPTH) {
        return false;
    }
    if (ep->n_native_watches > 0 && ep->native_epfd >= 0) {
        struct pollfd pfd = { .fd = ep->native_epfd, .events = POLLIN, .revents = 0 };
        if (poll_native(&pfd, 1, 0) > 0) {
            return true;
        }
    }
    for (size_t i = 0; i < ep->n_watches; i++) {
        const nfl_epoll_watch_t *watch = ep->watches[i];
        if (watch->disarmed) {
            continue;
        }
        const uint32_t interest = watch->events & kReadinessMask;
        if (interest && (sock_poll_depth(watch->target, interest, depth + 1) & interest)) {
            return true;
        }
    }
    return false;
}

static uint32_t sock_poll_depth(nfl_sock_full_t *sock, const uint32_t interest, const int depth) {
    if (sock->kind == NFL_FD_EPOLL) {
        if ((interest & EPOLLIN) && epoll_instance_ready(sock->epoll_data, depth)) {
            return EPOLLIN;
        }
        return 0;
    }
    return socket_poll(sock, interest);
}

uint32_t nfl_sock_poll(nfl_sock_full_t *sock, const uint32_t interest) {
    return sock_poll_depth(sock, interest, 0);
}

uint32_t sock_poll_with_gap(nfl_sock_full_t *sock, const uint32_t interest, const bool blocking) {
    uint32_t revents = nfl_sock_poll(sock, interest);
    if ((interest & EPOLLIN) && sock->recv_gap_pending) {
        sock->recv_gap_pending = false;
        if (!blocking) {
            revents &= ~(uint32_t)EPOLLIN;
        }
    }
    return revents;
}

int poll_nfl(struct pollfd *fds, const nfds_t nfds, const int timeout) {
    nfl_log("poll_nfl() called with nfds=%lu, timeout=%d", (unsigned long)nfds, timeout);

    const bool blocking = (timeout != 0);
    int amount_fds_with_event = 0;

    for (nfds_t i = 0; i < nfds; i++) {
        struct pollfd *current_poll_struct = &fds[i];
        current_poll_struct->revents = 0;

        nfl_sock_full_t *sock = get_nfl_sock(current_poll_struct->fd);
        if (!sock) {
            current_poll_struct->revents |= POLLNVAL;
            amount_fds_with_event++;
            continue;
        }

        const uint32_t interest = (uint32_t)(unsigned short)current_poll_struct->events;
        const uint32_t revents = sock_poll_with_gap(sock, interest, blocking);
        if (revents) {
            nfl_log("(p)poll(): event 0x%x for %s", revents, sock_to_str(sock));
            current_poll_struct->revents = (short)revents;
            amount_fds_with_event++;
            sock_idle_clear(sock);
        } else {
            sock_idle_tick(sock);
        }
    }

    nfl_log("poll_nfl() returning with nfds=%lu, timeout=%d, amount_fds_with_event=%d", (unsigned long)nfds, timeout, amount_fds_with_event);

    return amount_fds_with_event;
}

int select_nfl(const int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const bool blocking) {
    int res = 0;

    for (int fd = 0; fd < nfds; fd++) {
        const bool do_read = (readfds != NULL) && FD_ISSET(fd, readfds);
        const bool do_write = (writefds != NULL) && FD_ISSET(fd, writefds);
        const bool do_except = (exceptfds != NULL) && FD_ISSET(fd, exceptfds);
        if (!do_read && !do_write && !do_except) {
            continue;
        }

        nfl_sock_full_t *sock = get_nfl_sock(fd);
        if (!sock) {
            if (do_read) {
                FD_CLR(fd, readfds);
            }
            if (do_write) {
                FD_CLR(fd, writefds);
            }
            if (do_except) {
                FD_CLR(fd, exceptfds);
            }
            continue;
        }

        const uint32_t interest = (do_read ? EPOLLIN : 0U) | (do_write ? EPOLLOUT : 0U);
        const uint32_t revents = sock_poll_with_gap(sock, interest, blocking);

        if (revents) {
            sock_idle_clear(sock);
        } else {
            sock_idle_tick(sock);
        }

        if (do_read) {
            if (revents & EPOLLIN) {
                res++;
            } else {
                FD_CLR(fd, readfds);
            }
        }
        if (do_write) {
            if (revents & EPOLLOUT) {
                res++;
            } else {
                FD_CLR(fd, writefds);
            }
        }
        if (do_except) {
            FD_CLR(fd, exceptfds);
        }
    }
    return res;
}
