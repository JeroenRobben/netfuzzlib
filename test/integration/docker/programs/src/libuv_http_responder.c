/* libuv-driven TCP HTTP responder: same wire behavior as
 * http_get_responder.c, but listen/accept/read/write are dispatched through
 * libuv's event loop. Same eventfd-on-epoll gap as libuv_udp_echo. See
 * that file's header for the failure analysis. WILL_FAIL until the hybrid
 * epoll lands. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <uv.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char kResponse[] =
    "HTTP/1.1 200 OK\r\n"
    "Content-Length: 5\r\n"
    "Content-Type: text/plain\r\n"
    "\r\n"
    "hello";

struct conn_state {
    uv_tcp_t handle;
    char buf[4096];
    size_t off;
    uv_write_t write_req;
};

static void on_alloc(uv_handle_t *handle, size_t suggested_size, uv_buf_t *buf) {
    (void)suggested_size;
    struct conn_state *st = (struct conn_state *)handle;
    buf->base = st->buf + st->off;
    buf->len = sizeof(st->buf) - st->off;
}

static void on_close(uv_handle_t *handle) {
    free(handle->data);  /* Server uv_tcp_t holds a pointer to itself. Client conn_state is freed via st. */
}

static void on_write_done(uv_write_t *req, int status) {
    if (status < 0) {
        fprintf(stderr, "uv_write: %s\n", uv_strerror(status));
    }
    struct conn_state *st = (struct conn_state *)req->handle;
    uv_stop(st->handle.loop);
}

static void on_read(uv_stream_t *stream, ssize_t nread, const uv_buf_t *buf) {
    (void)buf;
    struct conn_state *st = (struct conn_state *)stream;
    if (nread < 0) {
        if (nread != UV_EOF) {
            fprintf(stderr, "read: %s\n", uv_strerror((int)nread));
        }
        uv_stop(stream->loop);
        return;
    }
    if (nread == 0) {
        return;
    }
    st->off += (size_t)nread;
    if (st->off >= 4 && memmem(st->buf, st->off, "\r\n\r\n", 4) != NULL) {
        uv_buf_t out = uv_buf_init((char *)kResponse, sizeof(kResponse) - 1);
        int rc = uv_write(&st->write_req, stream, &out, 1, on_write_done);
        if (rc < 0) {
            fprintf(stderr, "uv_write: %s\n", uv_strerror(rc));
            uv_stop(stream->loop);
        }
    }
}

static void on_connection(uv_stream_t *server, int status) {
    if (status < 0) {
        fprintf(stderr, "on_connection: %s\n", uv_strerror(status));
        uv_stop(server->loop);
        return;
    }
    struct conn_state *st = calloc(1, sizeof(*st));
    if (!st) {
        uv_stop(server->loop);
        return;
    }
    int rc = uv_tcp_init(server->loop, &st->handle);
    if (rc < 0) {
        fprintf(stderr, "uv_tcp_init: %s\n", uv_strerror(rc));
        free(st);
        uv_stop(server->loop);
        return;
    }
    rc = uv_accept(server, (uv_stream_t *)&st->handle);
    if (rc < 0) {
        fprintf(stderr, "uv_accept: %s\n", uv_strerror(rc));
        uv_close((uv_handle_t *)&st->handle, NULL);
        free(st);
        uv_stop(server->loop);
        return;
    }
    rc = uv_read_start((uv_stream_t *)&st->handle, on_alloc, on_read);
    if (rc < 0) {
        fprintf(stderr, "uv_read_start: %s\n", uv_strerror(rc));
        uv_stop(server->loop);
    }
}

int main(void) {
    uv_loop_t loop;
    int rc = uv_loop_init(&loop);
    if (rc < 0) {
        fprintf(stderr, "uv_loop_init: %s\n", uv_strerror(rc));
        return 1;
    }

    uv_tcp_t server;
    rc = uv_tcp_init(&loop, &server);
    if (rc < 0) { fprintf(stderr, "uv_tcp_init: %s\n", uv_strerror(rc)); return 1; }

    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = htons(8080);
    rc = uv_tcp_bind(&server, (const struct sockaddr *)&sa, 0);
    if (rc < 0) { fprintf(stderr, "uv_tcp_bind: %s\n", uv_strerror(rc)); return 1; }

    rc = uv_listen((uv_stream_t *)&server, 4, on_connection);
    if (rc < 0) { fprintf(stderr, "uv_listen: %s\n", uv_strerror(rc)); return 1; }

    rc = uv_run(&loop, UV_RUN_DEFAULT);
    if (rc < 0) {
        fprintf(stderr, "uv_run: %s\n", uv_strerror(rc));
        return 1;
    }

    return 0;
}
