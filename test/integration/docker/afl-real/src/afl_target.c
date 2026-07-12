/*
 * Tiny TCP target for the real-AFL integration test. Single accept,
 * single read, magic-bytes crash, exit. AFL drives this in fork-server
 * mode: the libnfl AFL module synthesises the connection and
 * delivers each AFL test case as the inbound packet.
 *
 * The bug: a NULL deref when the first four bytes of the request are
 * "BUG!". With afl-clang-fast coverage feedback this is reachable in
 * seconds. The magic-byte hint lets AFL escape each branch with a
 * single bit-flip. Used as the pass criterion for the test.
 */

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(void) {
    /* No AFL-specific code: the harness sets __AFL_DEFER_FORKSRV in the
     * env and libnfl-afl's nfl_setup calls
     * __afl_manual_init() during the netfuzzlib constructor. By the
     * time main() runs we're already in the per-iteration child of the
     * AFL fork-server with shmem fuzzing engaged. */
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    if (srv < 0) return 1;
    int yes = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(8095);
    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) < 0) return 1;
    if (listen(srv, 8) < 0) return 1;

    int conn = accept(srv, NULL, NULL);
    if (conn < 0) return 1;

    unsigned char buf[64];
    ssize_t n = read(conn, buf, sizeof(buf));
    if (n >= 4 && buf[0] == 'B' && buf[1] == 'U' && buf[2] == 'G' && buf[3] == '!') {
        /* The bug: AFL must steer to this branch via coverage feedback. */
        volatile char *p = NULL;
        *p = 1;
    }

    close(conn);
    close(srv);
    return 0;
}
