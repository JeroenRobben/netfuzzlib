/* libev-driven TCP HTTP responder: same wire behavior as
 * http_get_responder.c, but accept and read are dispatched through libev's
 * event loop. Backend (epoll/poll/select) is forced via argv[1]. See
 * libev_udp_echo.c for the assertion pattern. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static const char kResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 5\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "hello";

struct conn_state {
    char buf[4096];
    size_t off;
    ev_io read_watcher;
};

static unsigned int backend_flag(const char *want) {
    if (strcmp(want, "epoll") == 0) {
        return EVBACKEND_EPOLL;
    }
    if (strcmp(want, "poll") == 0) {
        return EVBACKEND_POLL;
    }
    if (strcmp(want, "select") == 0) {
        return EVBACKEND_SELECT;
    }
    return 0;
}

static int write_full(int fd, const void *data, size_t len) {
    const char *p = data;
    while (len > 0) {
        ssize_t m = write(fd, p, len);
        if (m < 0) {
            return -1;
        }
        p += (size_t)m;
        len -= (size_t)m;
    }
    return 0;
}

static void on_client_readable(struct ev_loop *loop, ev_io *w, int revents) {
    (void)revents;
    struct conn_state *st = (struct conn_state *)((char *)w - offsetof(struct conn_state, read_watcher));
    ssize_t n = read(w->fd, st->buf + st->off, sizeof(st->buf) - st->off);
    if (n <= 0) {
        fprintf(stderr, "read returned %zd\n", n);
        ev_io_stop(loop, &st->read_watcher);
        ev_break(loop, EVBREAK_ALL);
        free(st);
        return;
    }
    st->off += (size_t)n;
    if (st->off >= 4 && memmem(st->buf, st->off, "\r\n\r\n", 4) != NULL) {
        if (write_full(w->fd, kResponse, sizeof(kResponse) - 1) != 0) {
            perror("write");
        }
        ev_io_stop(loop, &st->read_watcher);
        ev_break(loop, EVBREAK_ALL);
        free(st);
    }
}

static void on_listener_readable(struct ev_loop *loop, ev_io *w, int revents) {
    (void)revents;
    int cs = accept(w->fd, NULL, NULL);
    if (cs < 0) {
        perror("accept");
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    struct conn_state *st = calloc(1, sizeof(*st));
    if (!st) {
        close(cs);
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    ev_io_init(&st->read_watcher, on_client_readable, cs, EV_READ);
    ev_io_start(loop, &st->read_watcher);
    /* on_client_readable owns st now and free()s it after the response is
     * written or on EOF. */
}

int main(int argc, char **argv) {
    const char *backend = (argc > 1) ? argv[1] : "epoll";
    unsigned int flags = backend_flag(backend);
    if (!flags) {
        fprintf(stderr, "unknown backend: %s\n", backend);
        return 1;
    }

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }

    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(8080);
    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0) { perror("bind"); return 1; }
    if (listen(ls, 4) < 0) { perror("listen"); return 1; }

    struct ev_loop *loop = ev_loop_new(flags);
    if (!loop) {
        fprintf(stderr, "ev_loop_new failed for backend=%s\n", backend);
        return 1;
    }
    if (ev_backend(loop) != flags) {
        fprintf(stderr, "backend mismatch: requested %s, libev picked 0x%x\n",
                backend, ev_backend(loop));
        ev_loop_destroy(loop);
        return 1;
    }

    ev_io listen_watcher;
    ev_io_init(&listen_watcher, on_listener_readable, ls, EV_READ);
    ev_io_start(loop, &listen_watcher);

    ev_run(loop, 0);

    ev_loop_destroy(loop);
    close(ls);
    return 0;
}
