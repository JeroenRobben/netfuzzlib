/* libuv-driven UDP echo: currently broken under nfl (WILL_FAIL). Failure
 * is `uv__io_poll: Assertion errno == EEXIST failed`: libuv tries to
 * epoll_ctl ADD its native async-wakeup eventfd onto the loop epoll, our
 * epoll_ctl_nfl returns EPERM (native fd in nfl epoll), libuv asserts. This
 * is the same eventfd-on-epoll gap libevent_threaded_udp_echo drives. When
 * the hybrid epoll lands and native fds can be hosted on an nfl epoll, the
 * assertion goes away and this starts passing. (The io_uring probing libuv
 * does at startup is harmless: our syscall-level stub returns ENOSYS for
 * SYS_io_uring_setup, forcing the epoll path.) */
#include <uv.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char g_recv_storage[1500];

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)handle; (void)suggested_size;
    buf->base = g_recv_storage;
    buf->len = sizeof(g_recv_storage);
}

static void on_send_done(uv_udp_send_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "uv_udp_send: %s\n", uv_strerror(status));
    }
    uv_stop(req->handle->loop);
    free(req);
}

static void on_recv(uv_udp_t *handle, ssize_t nread, const uv_buf_t *buf,
                    const struct sockaddr *addr, unsigned flags) {
    (void)flags;
    if (nread == 0 && addr == NULL) {
        return;  /* libuv signals "no more data this turn" with all-zero args */
    }
    if (nread < 0) {
        fprintf(stderr, "recv: %s\n", uv_strerror((int)nread));
        uv_stop(handle->loop);
        return;
    }
    uv_buf_t out = uv_buf_init(buf->base, (unsigned)nread);
    uv_udp_send_t *req = calloc(1, sizeof(*req));
    if (!req) {
        uv_stop(handle->loop);
        return;
    }
    int rc = uv_udp_send(req, handle, &out, 1, addr, on_send_done);
    if (rc < 0) {
        fprintf(stderr, "uv_udp_send: %s\n", uv_strerror(rc));
        free(req);
        uv_stop(handle->loop);
    }
}

int main(void) {
    uv_loop_t loop;
    int rc = uv_loop_init(&loop);
    if (rc < 0) {
        fprintf(stderr, "uv_loop_init: %s\n", uv_strerror(rc));
        return 1;
    }

    uv_udp_t udp;
    rc = uv_udp_init(&loop, &udp);
    if (rc < 0) { fprintf(stderr, "uv_udp_init: %s\n", uv_strerror(rc)); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(8888);
    rc = uv_udp_bind(&udp, (const struct sockaddr *)&sa, 0);
    if (rc < 0) { fprintf(stderr, "uv_udp_bind: %s\n", uv_strerror(rc)); return 1; }

    rc = uv_udp_recv_start(&udp, on_alloc, on_recv);
    if (rc < 0) { fprintf(stderr, "uv_udp_recv_start: %s\n", uv_strerror(rc)); return 1; }

    rc = uv_run(&loop, UV_RUN_DEFAULT);
    if (rc < 0) {
        fprintf(stderr, "uv_run: %s\n", uv_strerror(rc));
        return 1;
    }

    uv_close((uv_handle_t *)&udp, NULL);
    uv_run(&loop, UV_RUN_NOWAIT);
    uv_loop_close(&loop);
    return 0;
}
