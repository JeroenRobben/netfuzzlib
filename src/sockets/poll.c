#include "hooks/hooks.h"
#include <sys/select.h>
#include "environment/network_env.h"
#include "sockets_util.h"
#include "sockets_stream.h"
#include "environment/fd_table.h"
#include <poll.h>

bool sock_has_input_event(nfl_sock_t *sock) {
    if (sock->is_listening) {
        tcp_update_pending_connections(sock);
        return sock->tcp_pending != NULL;
    }
    return sock_recv_buffer_bytes_available(sock) > 0;
}

int poll_nfl(struct pollfd *fds, nfds_t nfds, int timeout) {
    nfl_log_info("poll_nfl() called with nfds=%d, timeout=%d", nfds, timeout);

    int amount_fds_with_event = 0;
    nfds_t i;
    nfl_sock_t *sock;

    for (i = 0; i < nfds; i++) {
        struct pollfd *current_poll_struct = &fds[i];
        bool sock_has_event = false;

        sock = get_nfl_sock(current_poll_struct->fd);
        current_poll_struct->revents = 0;

        if (!sock) {
            current_poll_struct->revents |= POLLNVAL;
            amount_fds_with_event++;
            continue;
        }

        if (IS_FLAG_SET(current_poll_struct->events, POLLIN) && sock_has_input_event(sock)) {
            nfl_log_debug("(p)poll(): incoming data available (POLLIN) for %s\n", sock_to_str(sock));
            current_poll_struct->revents |= POLLIN;
            sock_has_event = true;
        }
        if (IS_FLAG_SET(current_poll_struct->events, POLLOUT) && sock->remote_addr && !sock->shutdown_write) {
            current_poll_struct->revents |= POLLOUT;
            sock_has_event = true;
        }
        if (IS_FLAG_SET(current_poll_struct->events, POLLRDHUP) && sock->type == SOCK_STREAM && sock->shutdown_write) {
            current_poll_struct->revents |= POLLRDHUP;
            sock_has_event = true;
        }
        if (IS_FLAG_SET(current_poll_struct->events, POLLHUP) && sock->type == SOCK_STREAM && sock->shutdown_read) {
            current_poll_struct->revents |= POLLHUP;
            sock_has_event = true;
        }

        if (sock_has_event)
            amount_fds_with_event++;
    }

    nfl_log_info("poll_nfl() returning with nfds=%d, timeout=%d, amount_fds_with_event=%d", nfds, timeout, amount_fds_with_event);

    return amount_fds_with_event;
}

int select_nfl(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds) {
    nfl_sock_t *sock;
    int res = 0;
    bool do_read;
    bool do_write;
    bool do_except;

    for (int fd = 0; fd < nfds; fd++) {
        do_read = (readfds != NULL) && FD_ISSET(fd, readfds);
        do_write = (writefds != NULL) && FD_ISSET(fd, writefds);
        do_except = (exceptfds != NULL) && FD_ISSET(fd, exceptfds);
        if (!do_read && !do_write && !do_except) {
            continue;
        }

        sock = get_nfl_sock(fd);
        if (!sock) {
            if (do_read) {
                FD_CLR(fd, readfds);
            }
            if (do_except) {
                FD_CLR(fd, writefds);
            }
            if (do_write) {
                FD_CLR(fd, exceptfds);
            }
            continue;
        }
        if (do_read) {
            if (sock_has_input_event(sock)) {
                res++;
            } else {
                FD_CLR(fd, readfds);
            }
        }
        if (do_write) {
            if (sock->remote_addr && !sock->shutdown_write) {
                res++;
            } else {
                FD_CLR(fd, writefds);
            }
        }

        if (do_except) {
            FD_CLR(fd, exceptfds);
        } //No behaviour that could lead to exceptional conditions applicable to model
    }
    return res;
}