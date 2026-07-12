#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"

#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>

#include <netfuzzlib/api.h>
#include <netfuzzlib/log.h>
#include <netfuzzlib/callbacks.h>

#include "afl_init.h"
#include "child_tracker.h"
#include "config.h"

extern int __afl_sharedmem_fuzzing __attribute__((weak));
extern unsigned int *__afl_fuzz_len __attribute__((weak));
extern unsigned char *__afl_fuzz_ptr __attribute__((weak));

// Set once the SUT's first accept/connect on NFL_PORT has been granted, so the
// TCP endpoint is handed out exactly once.
static bool endpoint_granted;

static int afl_runtime_present(void) {
    return (&__afl_fuzz_ptr != NULL && __afl_fuzz_ptr != NULL);
}

static unsigned int afl_input_len(void) {
    if (afl_runtime_present() && &__afl_fuzz_len != NULL && __afl_fuzz_len != NULL) {
        return *__afl_fuzz_len;
    }
    return 0;
}

static const unsigned char *afl_input_ptr(void) {
    return afl_runtime_present() ? __afl_fuzz_ptr : NULL;
}

static void set_stop_fuzzing(bool v) {
    afl_get_config()->stop_fuzzing = v;
}

/* Synthetic peer endpoint. The IP family follows the SUT's socket domain. */
enum { AFL_FUZZER_PORT_HOST = 1234 };

static void fill_loopback_addr(nfl_addr_t *out, int domain, uint16_t port_net) {
    memset(out, 0, sizeof(*out));
    if (domain == AF_INET) {
        out->s4.sin_family = AF_INET;
        out->s4.sin_port = port_net;
        out->s4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else if (domain == AF_INET6) {
        out->s6.sin6_family = AF_INET6;
        out->s6.sin6_port = port_net;
        out->s6.sin6_addr = in6addr_loopback;
    }
}

static bool addr_port_is(const nfl_addr_t *addr, uint16_t port_net) {
    if (!addr) return false;
    if (addr->s.sa_family == AF_INET) return addr->s4.sin_port == port_net;
    if (addr->s.sa_family == AF_INET6) return addr->s6.sin6_port == port_net;
    return false;
}

static bool is_fuzz_endpoint(const nfl_sock_t *sock, uint16_t port_net) {
    return addr_port_is(sock->local_addr, port_net) ||
           addr_port_is(sock->remote_addr, port_net);
}

int nfl_setup(void) {
    memset(afl_get_config(), 0, sizeof(afl_module_config));
    if (afl_load_config() != 0) {
        nfl_log("afl: load config failed");
        return -1;
    }
    if (&__afl_sharedmem_fuzzing != NULL) {
        __afl_sharedmem_fuzzing = 1;
    }
    return 0;
}

bool nfl_tcp_connect(const nfl_sock_t *sock, const nfl_addr_t *remote_addr) {
    (void)sock;
    afl_module_config *cfg = afl_get_config();
    if (cfg->stop_fuzzing) return false;
    if (!addr_port_is(remote_addr, cfg->sut_port_net)) return false;
    endpoint_granted = true;
    return true;
}

bool nfl_tcp_accept(const nfl_sock_t *sock, nfl_addr_t *remote_addr) {
    afl_module_config *cfg = afl_get_config();
    if (cfg->stop_fuzzing) return false;
    if (!addr_port_is(sock->local_addr, cfg->sut_port_net)) return false;
    if (endpoint_granted) return false; // one connection per run

    if (!getenv("__AFL_DEFER_FORKSRV")) {
        afl_child_tracker_reset();
    }
    endpoint_granted = true;
    fill_loopback_addr(remote_addr, sock->domain, htons(AFL_FUZZER_PORT_HOST));
    nfl_log("afl: first accept granted");
    return true;
}

void nfl_socket_idle(const nfl_sock_t *sock) {
    (void)sock;
    if (!nfl_all_sockets_in_process_idle()) {
        return;
    }
    nfl_log("afl: all sockets idle, reaping tracked children");
    afl_child_tracker_wait_all();
    exit(0);
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    *pkt = NULL;
    afl_module_config *cfg = afl_get_config();
    if (cfg->stop_fuzzing) return NFL_CONN_OK;
    if (!is_fuzz_endpoint(sock, cfg->sut_port_net)) return NFL_CONN_OK;

    // Forkserver entry, latest safe point. See SnapFuzz paper.
    afl_lazy_manual_init();

    const unsigned int len = afl_input_len();
    nfl_pkt *p = nfl_alloc_pkt(len);
    if (!p) return NFL_CONN_OK;
    if (len) {
        memcpy(p->buf, afl_input_ptr(), len);
    }
    *pkt = p;
    set_stop_fuzzing(true);

    // UDP needs a source (and destination, for IP_PKTINFO); TCP ignores info.
    if (sock->protocol != IPPROTO_TCP) {
        fill_loopback_addr(&info->src_addr, sock->domain, htons(AFL_FUZZER_PORT_HOST));
        fill_loopback_addr(&info->dst_addr, sock->domain, cfg->sut_port_net);
    }
    info->iface_index = 1;
    return NFL_CONN_OK;
}

#pragma clang diagnostic pop
