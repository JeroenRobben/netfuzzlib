/* Replay module: hands the SUT a prerecorded byte transcript as the peer's
 * side of a connection, and discards everything the SUT sends. The transcript
 * path comes from NFL_REPLAY_TRANSCRIPT.
 *
 * This drives a client target (e.g. ssh-keyscan) through a recorded server
 * handshake with no live peer, so the exchange is deterministic and hermetic:
 * the bytes are available synchronously from the module, which sidesteps the
 * "poll never waits for a real peer" problem the kernel-bridge module has when
 * a non-blocking client polls for a reply that is a real network round-trip
 * away. See docs/message_boundaries.md for the gap semantics that let a
 * blocking read/poll consume the recorded packets back to back.
 *
 * The whole transcript is delivered as one SOCK_STREAM packet; the target
 * de-frames it at its own pace (SSH reads the banner byte by byte, then
 * length-prefixed binary packets). Outbound data is dropped via the weak
 * nfl_send default. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netfuzzlib/api.h>
#include <netfuzzlib/callbacks.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned char *g_data = NULL;
static size_t g_len = 0;
static bool g_delivered = false;

int nfl_setup(void) {
    const char *path = getenv("NFL_REPLAY_TRANSCRIPT");
    if (!path || !*path) {
        nfl_log("replay: NFL_REPLAY_TRANSCRIPT not set");
        return -1;
    }
    FILE *f = fopen(path, "rb");
    if (!f) {
        nfl_log("replay: cannot open %s: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (g_len = (size_t)ftell(f)) == (size_t)-1) {
        fclose(f);
        nfl_log("replay: cannot size %s", path);
        return -1;
    }
    rewind(f);
    g_data = malloc(g_len ? g_len : 1);
    if (!g_data) {
        fclose(f);
        nfl_log("replay: out of memory for %zu bytes", g_len);
        return -1;
    }
    if (g_len && fread(g_data, 1, g_len, f) != g_len) {
        fclose(f);
        nfl_log("replay: short read on %s", path);
        return -1;
    }
    fclose(f);
    nfl_log("replay: loaded %zu bytes from %s", g_len, path);
    return 0;
}

bool nfl_tcp_connect(const nfl_sock_t *sock, const nfl_addr_t *remote_addr) {
    (void)sock;
    (void)remote_addr;
    return true; // the recorded peer always accepts the connection
}

bool nfl_tcp_accept(const nfl_sock_t *sock, nfl_addr_t *remote_addr) {
    (void)sock;
    (void)remote_addr;
    return false; // replay drives client-side targets; no inbound connections
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    (void)sock;
    (void)info;
    if (g_delivered || g_len == 0) {
        return NFL_CONN_OK; // transcript already handed over; nothing more to send
    }
    nfl_pkt *p = nfl_alloc_pkt(g_len);
    if (!p) {
        return NFL_CONN_OK; // allocation failed; retry on the next read
    }
    memcpy(p->buf, g_data, g_len);
    *pkt = p;
    g_delivered = true;
    return NFL_CONN_OK;
}
