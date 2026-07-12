/* Spec-test module: fixed eth0 / TEST-NET-1 ground truth + in-process
 * loopback delivery queue so UDP send/recv tests run identically on the
 * model and the real kernel. */
#include <netfuzzlib/callbacks.h>
#include "core/addr.h"
#include "core/interfaces.h"
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

int nfl_setup() {
    static const char eth_mac[ETHER_ADDR_LEN]     = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x01 };
    static const char eth_brd_mac[ETHER_ADDR_LEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    unsigned int idx = 0;
    if (nfl_add_l2_iface("eth0", IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_RUNNING,
                         1500, eth_mac, eth_brd_mac, &idx) != 0) {
        return -1;
    }
    if (nfl_add_l3_iface_ipv4(idx, "192.0.2.1", "255.255.255.0") != 0) {
        return -1;
    }
    if (nfl_add_l3_iface_ipv6(idx, "2001:db8::1", 64, 0x0) != 0) {
        return -1;
    }
    return 0;
}

bool nfl_tcp_connect(const nfl_sock_t *sock,
                     const nfl_addr_t *remote_addr) {
    (void)sock;
    (void)remote_addr;
    return false;
}

static int pending_accepts = 0;

void module_test_set_pending_tcp_accepts(int n) {
    pending_accepts = n;
}

bool nfl_tcp_accept(const nfl_sock_t *sock,
                    nfl_addr_t *remote_addr) {
    if (pending_accepts <= 0) {
        return false;
    }
    pending_accepts--;
    if (sock->domain == AF_INET) {
        remote_addr->s4.sin_family = AF_INET;
        remote_addr->s4.sin_port = htons(54321);
        inet_pton(AF_INET, "127.0.0.1", &remote_addr->s4.sin_addr);
    } else if (sock->domain == AF_INET6) {
        remote_addr->s6.sin6_family = AF_INET6;
        remote_addr->s6.sin6_port = htons(54321);
        inet_pton(AF_INET6, "::1", &remote_addr->s6.sin6_addr);
    }
    return true;
}

/* --- loopback delivery queue ------------------------------------------- */

/* Holds the sent bytes in a module-owned queue. At delivery time (nfl_receive)
 * the bytes are copied into a packet from nfl_alloc_pkt() that the framework
 * then owns. */
typedef struct queued_pkt {
    void *buf;
    size_t len;
    nfl_addr_t local_addr;
    nfl_addr_t remote_addr;
    struct queued_pkt *next;
} queued_pkt;

static queued_pkt *pending_head = NULL;
static queued_pkt **pending_tail = &pending_head;

/* Match on family and port, address either exact or receiver bound wildcard. */
static bool addr_matches_bound(const nfl_addr_t *pkt_dst, const nfl_addr_t *bound) {
    if (pkt_dst->s.sa_family != bound->s.sa_family) {
        return false;
    }
    if (pkt_dst->s.sa_family == AF_INET) {
        if (pkt_dst->s4.sin_port != bound->s4.sin_port) {
            return false;
        }
        if (bound->s4.sin_addr.s_addr == INADDR_ANY) {
            return true;
        }
        return pkt_dst->s4.sin_addr.s_addr == bound->s4.sin_addr.s_addr;
    }
    if (pkt_dst->s.sa_family == AF_INET6) {
        if (pkt_dst->s6.sin6_port != bound->s6.sin6_port) {
            return false;
        }
        if (IN6_IS_ADDR_UNSPECIFIED(&bound->s6.sin6_addr)) {
            return true;
        }
        return memcmp(&pkt_dst->s6.sin6_addr,
                      &bound->s6.sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    }
    return false;
}

void module_test_reset_pending_packets(void) {
    while (pending_head) {
        queued_pkt *q = pending_head;
        pending_head = q->next;
        free(q->buf);
        free(q);
    }
    pending_tail = &pending_head;
}

static bool send_closed = false;

void module_test_set_send_closed(bool closed) {
    send_closed = closed;
}

static bool recv_closed = false;

void module_test_set_recv_closed(bool closed) {
    recv_closed = closed;
}

nfl_conn_result nfl_send(const nfl_sock_t *sock,
                         const nfl_addr_t *to,
                         const struct iovec *iov,
                         const size_t iovlen) {
    if (send_closed) {
        return NFL_CONN_CLOSED;
    }
    const ssize_t total = iov_count_bytes(iov, iovlen);
    if (total < 0) {
        return NFL_CONN_OK;
    }

    queued_pkt *q = calloc(1, sizeof(queued_pkt));
    if (!q) {
        return NFL_CONN_OK;
    }
    // A zero-length UDP datagram is valid and must still round-trip, so queue it
    // with a NULL buffer rather than dropping it.
    if (total > 0) {
        q->buf = malloc((size_t)total);
        if (!q->buf) {
            free(q);
            return NFL_CONN_OK;
        }
        char *dst = q->buf;
        size_t off = 0;
        for (size_t i = 0; i < iovlen; i++) {
            memcpy(dst + off, iov[i].iov_base, iov[i].iov_len);
            off += iov[i].iov_len;
        }
    }
    q->len = (size_t)total;

    /* From the receiver's POV: dest = local, source = peer (this sender). */
    q->local_addr = *to;
    q->remote_addr = *sock->local_addr;
    q->next = NULL;
    *pending_tail = q;
    pending_tail = &q->next;

    return NFL_CONN_OK;
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    *pkt = NULL;
    if (recv_closed) {
        return NFL_CONN_CLOSED; // simulate a peer that closed its end (EOF)
    }
    if (!sock->local_addr) {
        return NFL_CONN_OK;
    }
    queued_pkt **cursor = &pending_head;
    while (*cursor) {
        queued_pkt *q = *cursor;
        if (addr_matches_bound(&q->local_addr, sock->local_addr)) {
            nfl_pkt *p = nfl_alloc_pkt(q->len);
            if (!p) {
                return NFL_CONN_OK; // leave queued; retry on the next call
            }
            if (q->len > 0) {
                memcpy(p->buf, q->buf, q->len);
            }
            *pkt = p;

            info->src_addr = q->remote_addr;
            info->dst_addr = q->local_addr;
            info->iface_index = 1;

            *cursor = q->next;
            if (!*cursor) {
                pending_tail = cursor;
            }
            free(q->buf);
            free(q);
            return NFL_CONN_OK;
        }
        cursor = &q->next;
    }
    return NFL_CONN_OK;
}
