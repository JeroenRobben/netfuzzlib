#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netfuzzlib/api.h>
#include <netfuzzlib/callbacks.h>

#define HELLO_WORLD_MSG "Hello world\r\n"

int nfl_setup() {
    return 0;
}

bool nfl_tcp_connect(const nfl_sock_t *sock, const nfl_addr_t *remote_addr) {
    (void)sock;
    (void)remote_addr;
    return true;
}

bool nfl_tcp_accept(const nfl_sock_t *sock, nfl_addr_t *remote_addr) {
    static bool accept_done = false;
    if (accept_done) {
        return false;
    }
    accept_done = true;

    if (sock->domain == AF_INET) {
        remote_addr->s4.sin_family = AF_INET;
        remote_addr->s4.sin_port = htons(5678);
        inet_pton(AF_INET, "1.2.3.4", &remote_addr->s4.sin_addr);
    } else if (sock->domain == AF_INET6) {
        remote_addr->s6.sin6_family = AF_INET6;
        remote_addr->s6.sin6_port = htons(5678);
        inet_pton(AF_INET6, "::1234", &remote_addr->s6.sin6_addr);
    }
    return true;
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    static bool packet_sent = false;
    if (packet_sent) {
        return NFL_CONN_OK;
    }
    nfl_pkt *p = nfl_alloc_pkt(sizeof(HELLO_WORLD_MSG));
    if (!p) {
        return NFL_CONN_OK;
    }
    memcpy(p->buf, HELLO_WORLD_MSG, sizeof(HELLO_WORLD_MSG));
    packet_sent = true;
    *pkt = p;

    info->iface_index = 1;
    if (sock->domain == AF_INET) {
        info->src_addr.s4.sin_family = info->dst_addr.s4.sin_family = AF_INET;
        inet_pton(AF_INET, "127.0.0.1", &info->src_addr.s4.sin_addr);
        inet_pton(AF_INET, "127.0.0.1", &info->dst_addr.s4.sin_addr);
        info->src_addr.s4.sin_port = htons(9999);
        if (sock->local_addr) {
            info->dst_addr.s4.sin_port = sock->local_addr->s4.sin_port;
        }
    } else if (sock->domain == AF_INET6) {
        info->src_addr.s6.sin6_family = info->dst_addr.s6.sin6_family = AF_INET6;
        inet_pton(AF_INET6, "::1", &info->src_addr.s6.sin6_addr);
        inet_pton(AF_INET6, "::1", &info->dst_addr.s6.sin6_addr);
        info->src_addr.s6.sin6_port = htons(9999);
        if (sock->local_addr) {
            info->dst_addr.s6.sin6_port = sock->local_addr->s6.sin6_port;
        }
    }
    return NFL_CONN_OK;
}
