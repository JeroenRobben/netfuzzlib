/* Minimal accept-fork-per-conn TCP server. Exercises the AFL module's
 * child-pid tracker. The test asserts every forked PID gets reaped. */

#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static int parse_port(void) {
    const char *p = getenv("TCP_FORK_PORT");
    if (!p) return 8090;
    long v = strtol(p, NULL, 10);
    if (v <= 0 || v > 65535) return 8090;
    return (int)v;
}

static void handle_connection(int conn_fd) {
    char buf[64];
    ssize_t n = read(conn_fd, buf, sizeof(buf));
    fprintf(stderr, "[child %d] read %zd bytes\n", (int)getpid(), n);
    static const char resp[] = "ack\n";
    ssize_t w = write(conn_fd, resp, sizeof(resp) - 1);
    (void)w;
    close(conn_fd);
}

int main(void) {
    setvbuf(stderr, NULL, _IOLBF, 0);
    const int port = parse_port();
    fprintf(stderr, "[server %d] listening on 127.0.0.1:%d\n", (int)getpid(), port);

    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) {
        perror("socket");
        return 1;
    }
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }
    if (listen(srv, 8) < 0) {
        perror("listen");
        return 1;
    }

    for (;;) {
        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int conn = accept(srv, (struct sockaddr *)&peer, &plen);
        if (conn < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            return 1;
        }
        pid_t child = fork();
        if (child < 0) {
            perror("fork");
            close(conn);
            continue;
        }
        if (child == 0) {
            close(srv);
            handle_connection(conn);
            _exit(0);
        }
        fprintf(stderr, "[server %d] forked child %d\n", (int)getpid(), (int)child);
        close(conn);
    }
}
