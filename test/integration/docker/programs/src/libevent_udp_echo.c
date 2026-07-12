/* libevent-driven UDP echo: same wire behavior as udp_echo.c, but the read
 * side is driven by libevent's event_base. Backend (epoll/poll/select) is
 * forced via argv[1] so a single program can exercise every libevent I/O
 * backend nfl needs to support on Linux. event_config_avoid_method is used
 * to disable the other two. event_base_get_method is then asserted against
 * the requested name so a libevent that silently fell back to a different
 * backend fails the test instead of masquerading as a pass. */
#include <event2/event.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static void on_readable(evutil_socket_t fd, short what, void *arg) {
    (void)what;
    struct event_base *base = arg;
    char buf[1500];
    struct sockaddr_in from;
    socklen_t fromlen = sizeof(from);
    ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&from, &fromlen);
    if (n < 0) {
        perror("recvfrom");
        event_base_loopexit(base, NULL);
        return;
    }
    ssize_t m = sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&from, fromlen);
    if (m != n) {
        perror("sendto");
    }
    event_base_loopexit(base, NULL);
}

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

int main(int argc, char **argv) {
    const char *backend = (argc > 1) ? argv[1] : "epoll";

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

    struct event_base *base = make_base_for_backend(backend);
    if (!base) {
        return 1;
    }

    struct event *ev = event_new(base, s, EV_READ, on_readable, base);
    if (!ev) { fprintf(stderr, "event_new failed\n"); return 1; }
    if (event_add(ev, NULL) < 0) { fprintf(stderr, "event_add failed\n"); return 1; }

    int rc = event_base_dispatch(base);
    if (rc < 0) {
        fprintf(stderr, "event_base_dispatch failed: %d\n", rc);
        return 1;
    }

    event_free(ev);
    event_base_free(base);
    close(s);
    return 0;
}
