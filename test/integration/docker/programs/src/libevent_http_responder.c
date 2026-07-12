/* libevent-driven TCP HTTP responder: same wire behavior as
 * http_get_responder.c (accept one connection, read until "\r\n\r\n", write
 * a fixed HTTP/1.1 200, close), but the accept and read are dispatched
 * through libevent's event_base. Backend (epoll/poll/select) is forced via
 * argv[1], so a single binary covers every libevent I/O backend nfl needs to
 * support on Linux. event_base_get_method is asserted post-facto so a silent
 * fallback fails the test instead of masquerading as a pass. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <event2/event.h>

#include <arpa/inet.h>
#include <netinet/in.h>
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
    int fd;
    char buf[4096];
    size_t off;
    struct event *read_ev;
    struct event_base *base;
};

static struct event_base *make_base_for_backend(const char *want) {
    static const char *const all[] = {"epoll", "poll", "select", NULL};
    int known = 0;
    for (const char *const *m = all; *m; m++) {
        if (strcmp(*m, want) == 0) { known = 1; break; }
    }
    if (!known) {
        fprintf(stderr, "unknown backend: %s\n", want);
        return NULL;
    }
    struct event_config *cfg = event_config_new();
    if (!cfg) {
        return NULL;
    }
    for (const char *const *m = all; *m; m++) {
        if (strcmp(*m, want) != 0) {
            event_config_avoid_method(cfg, *m);
        }
    }
    struct event_base *base = event_base_new_with_config(cfg);
    event_config_free(cfg);
    if (!base) {
        fprintf(stderr, "event_base_new_with_config failed for backend=%s\n", want);
        return NULL;
    }
    const char *got = event_base_get_method(base);
    if (!got || strcmp(got, want) != 0) {
        fprintf(stderr, "backend mismatch: requested %s, libevent picked %s\n",
                want, got ? got : "(null)");
        event_base_free(base);
        return NULL;
    }
    return base;
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

static void release_conn(struct conn_state *st) {
    event_free(st->read_ev);
    free(st);
}

static void on_client_readable(evutil_socket_t fd, short what, void *arg) {
    (void)what;
    struct conn_state *st = arg;
    ssize_t n = read(fd, st->buf + st->off, sizeof(st->buf) - st->off);
    if (n <= 0) {
        fprintf(stderr, "read returned %zd\n", n);
        event_base_loopexit(st->base, NULL);
        release_conn(st);
        return;
    }
    st->off += (size_t)n;
    if (st->off >= 4 && memmem(st->buf, st->off, "\r\n\r\n", 4) != NULL) {
        if (write_full(fd, kResponse, sizeof(kResponse) - 1) != 0) {
            perror("write");
        }
        event_base_loopexit(st->base, NULL);
        release_conn(st);
    }
}

static void on_listener_readable(evutil_socket_t lfd, short what, void *arg) {
    (void)what;
    struct event_base *base = arg;
    int cs = accept(lfd, NULL, NULL);
    if (cs < 0) {
        perror("accept");
        event_base_loopexit(base, NULL);
        return;
    }
    struct conn_state *st = calloc(1, sizeof(*st));
    if (!st) {
        close(cs);
        event_base_loopexit(base, NULL);
        return;
    }
    st->fd = cs;
    st->base = base;
    st->read_ev = event_new(base, cs, EV_READ | EV_PERSIST, on_client_readable, st);
    if (!st->read_ev || event_add(st->read_ev, NULL) < 0) {
        fprintf(stderr, "event_new/event_add for client failed\n");
        if (st->read_ev) {
            event_free(st->read_ev);
        }
        free(st);
        close(cs);
        event_base_loopexit(base, NULL);
        return;
    }
    /* on_client_readable owns st now. It free()s via release_conn after the
     * response is written or on EOF. */
}

int main(int argc, char **argv) {
    const char *backend = (argc > 1) ? argv[1] : "epoll";

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

    struct event_base *base = make_base_for_backend(backend);
    if (!base) {
        return 1;
    }

    struct event *listen_ev = event_new(base, ls, EV_READ | EV_PERSIST,
                                        on_listener_readable, base);
    if (!listen_ev || event_add(listen_ev, NULL) < 0) {
        fprintf(stderr, "event_new/event_add for listener failed\n");
        return 1;
    }

    int rc = event_base_dispatch(base);
    if (rc < 0) {
        fprintf(stderr, "event_base_dispatch failed: %d\n", rc);
        return 1;
    }

    event_free(listen_ev);
    event_base_free(base);
    close(ls);
    return 0;
}
