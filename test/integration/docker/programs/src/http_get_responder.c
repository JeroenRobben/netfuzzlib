/* Vanilla TCP server: listen, accept one connection, read request bytes
 * until "\r\n\r\n", reply with a fixed HTTP/1.1 response, close. No netfuzzlib
 * awareness. LD_PRELOAD redirects sockets into the model. */
#define _GNU_SOURCE
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

int main(void) {
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

    struct sockaddr_in peer;
    socklen_t plen = sizeof(peer);
    int cs = accept(ls, (struct sockaddr *)&peer, &plen);
    if (cs < 0) { perror("accept"); return 1; }

    char buf[4096];
    size_t off = 0;
    while (off < sizeof(buf)) {
        ssize_t n = read(cs, buf + off, sizeof(buf) - off);
        if (n < 0) { perror("read"); return 1; }
        if (n == 0) {
            break;
        }
        off += (size_t)n;
        if (off >= 4 && memmem(buf, off, "\r\n\r\n", 4) != NULL) {
            break;
        }
    }

    size_t to_write = sizeof(kResponse) - 1;
    const char *p = kResponse;
    while (to_write > 0) {
        ssize_t m = write(cs, p, to_write);
        if (m < 0) { perror("write"); return 1; }
        p += m;
        to_write -= (size_t)m;
    }

    close(cs);
    close(ls);
    return 0;
}
