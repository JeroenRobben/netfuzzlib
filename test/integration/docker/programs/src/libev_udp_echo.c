/* libev-driven UDP echo: same wire behavior as udp_echo.c, but the read
 * side is dispatched through libev's event loop. Backend (epoll/poll/select)
 * is forced via argv[1]: ev_loop_new is given exactly one EVBACKEND_* bit so
 * libev returns NULL rather than silently picking another backend, and
 * ev_backend() is asserted post-fact for belt-and-braces. */
#include <ev.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void on_readable(struct ev_loop *loop, ev_io *w, int revents) {
    (void)revents;
    char buf[1500];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(w->fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
        perror("recvfrom");
        ev_break(loop, EVBREAK_ALL);
        return;
    }
    ssize_t m = sendto(w->fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fromlen);
    if (m != n) {
        perror("sendto");
    }
    ev_break(loop, EVBREAK_ALL);
}

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

int main(int argc, char **argv) {
    const char *backend = (argc > 1) ? argv[1] : "epoll";
    unsigned int flags = backend_flag(backend);
    if (!flags) {
        fprintf(stderr, "unknown backend: %s\n", backend);
        return 1;
    }

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0) { perror("socket"); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(8888);
    if (bind(s, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("bind");
        return 1;
    }

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

    ev_io watcher;
    ev_io_init(&watcher, on_readable, s, EV_READ);
    ev_io_start(loop, &watcher);

    ev_run(loop, 0);

    ev_loop_destroy(loop);
    close(s);
    return 0;
}
