/* Threaded libevent UDP echo. evthread_use_pthreads makes libevent allocate
 * an internal wakeup eventfd and register it on the same epoll instance our
 * UDP socket lives on. Because we don't intercept eventfd(), the wakeup fd
 * is a native kernel handle. epoll_ctl_nfl rejects native fds with EPERM,
 * libevent's epoll backend declares itself unusable, and event_base
 * construction fails (we pin the backend with event_config_avoid_method, so
 * there's no silent fallback to poll/select).
 *
 * This program is the failing-test driver for the hybrid-epoll work: today
 * it must exit non-zero, and the matching CTest entry is marked WILL_FAIL.
 * Once nfl can host native fds on an epoll instance, this passes and the
 * WILL_FAIL property comes off. */
#include <event2/event.h>
#include <event2/thread.h>

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

int main(void) {
    if (evthread_use_pthreads() != 0) {
        fprintf(stderr, "evthread_use_pthreads failed\n");
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

    /* Pin epoll: avoid silent fallback to poll/select if epoll init fails. */
    struct event_config *cfg = event_config_new();
    if (!cfg) { fprintf(stderr, "event_config_new failed\n"); return 1; }
    event_config_avoid_method(cfg, "poll");
    event_config_avoid_method(cfg, "select");
    struct event_base *base = event_base_new_with_config(cfg);
    event_config_free(cfg);
    if (!base) {
        fprintf(stderr, "event_base_new_with_config(epoll, threaded) failed\n");
        return 1;
    }
    const char *got = event_base_get_method(base);
    if (!got || strcmp(got, "epoll") != 0) {
        fprintf(stderr, "expected epoll, got %s\n", got ? got : "(null)");
        event_base_free(base);
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
    libevent_global_shutdown();
    close(s);
    return 0;
}
