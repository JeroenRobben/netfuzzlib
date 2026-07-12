/* Scripted module for integration tests. NFL_TEST_SCENARIO file directives:
 *
 *   deliver     to=A.B.C.D:port from=A.B.C.D:port [hex=...]
 *   expect      from=A.B.C.D:port to=A.B.C.D:port [hex=...]
 *   tcp_accept  on=A.B.C.D:port  from=A.B.C.D:port
 *   tcp_connect to=A.B.C.D:port
 *   drain_sends N
 *
 * IPv6: [::1]:port. Port=0 is wildcard. '#' and blank lines ignored.
 * A mismatch _exit(99)s. Unconsumed expects fail at atexit. */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <netfuzzlib/api.h>
#include <netfuzzlib/callbacks.h>
#include "core/addr.h"
#include "core/interfaces.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    /* deliver uses pkt dst/src, expect uses SUT-side local/peer. */
    nfl_addr_t local_addr;
    nfl_addr_t remote_addr;
    unsigned char *payload;
    size_t payload_len;
} pkt_spec;

typedef struct deliver_node { pkt_spec p; struct deliver_node *next; } deliver_node;
typedef struct expect_node  { pkt_spec p; struct expect_node *next; }  expect_node;

typedef struct accept_node {
    nfl_addr_t local_addr;
    nfl_addr_t remote_addr;
    struct accept_node *next;
} accept_node;

typedef struct connect_node {
    nfl_addr_t remote_addr;       /* destination the SUT must connect to */
    struct connect_node *next;
} connect_node;

static deliver_node *delivers_head = NULL;
static deliver_node **delivers_tail = &delivers_head;
static expect_node  *expects_head = NULL;
static expect_node  **expects_tail = &expects_head;
static accept_node  *accepts_head = NULL;
static accept_node  **accepts_tail = &accepts_head;
static connect_node *connects_head = NULL;
static connect_node **connects_tail = &connects_head;
static int drain_sends_remaining = 0;

#define EXIT_SCENARIO_FAIL 99

static void die(const char *msg) {
    fprintf(stderr, "nfl-scripted: %s\n", msg);
    fflush(stderr);
    _exit(EXIT_SCENARIO_FAIL);
}

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *hex, unsigned char **out, size_t *out_len) {
    size_t hl = strlen(hex);
    if ((hl % 2) != 0) return -1;
    size_t bl = hl / 2;
    unsigned char *buf = bl > 0 ? malloc(bl) : NULL;
    if (bl > 0 && !buf) return -1;
    for (size_t i = 0; i < bl; i++) {
        int v1 = hex_nibble(hex[2 * i]);
        int v2 = hex_nibble(hex[2 * i + 1]);
        if (v1 < 0 || v2 < 0) { free(buf); return -1; }
        buf[i] = (unsigned char)((v1 << 4) | v2);
    }
    *out = buf;
    *out_len = bl;
    return 0;
}

static int parse_addr(const char *s, nfl_addr_t *out) {
    memset(out, 0, sizeof(*out));
    if (s[0] == '[') {
        const char *rb = strchr(s, ']');
        if (!rb || rb[1] != ':') return -1;
        char host[64];
        size_t n = (size_t)(rb - s - 1);
        if (n == 0 || n >= sizeof(host)) return -1;
        memcpy(host, s + 1, n);
        host[n] = '\0';
        long port = strtol(rb + 2, NULL, 10);
        if (port < 0 || port > 65535) return -1;
        out->s6.sin6_family = AF_INET6;
        out->s6.sin6_port = htons((uint16_t)port);
        return inet_pton(AF_INET6, host, &out->s6.sin6_addr) == 1 ? 0 : -1;
    }
    const char *colon = strrchr(s, ':');
    if (!colon) return -1;
    char host[64];
    size_t n = (size_t)(colon - s);
    if (n == 0 || n >= sizeof(host)) return -1;
    memcpy(host, s, n);
    host[n] = '\0';
    long port = strtol(colon + 1, NULL, 10);
    if (port < 0 || port > 65535) return -1;
    out->s4.sin_family = AF_INET;
    out->s4.sin_port = htons((uint16_t)port);
    return inet_pton(AF_INET, host, &out->s4.sin_addr) == 1 ? 0 : -1;
}

static char *trim(char *s) {
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) e--;
    *e = '\0';
    return s;
}

static const char *find_kv(const char *line, const char *key) {
    size_t klen = strlen(key);
    const char *p = line;
    while ((p = strstr(p, key)) != NULL) {
        bool ok_left = (p == line) || isspace((unsigned char)p[-1]);
        if (ok_left && p[klen] == '=') {
            return p + klen + 1;
        }
        p += klen;
    }
    return NULL;
}

static char *take_token(const char *s) {
    const char *e = s;
    while (*e && !isspace((unsigned char)*e)) e++;
    size_t n = (size_t)(e - s);
    char *r = malloc(n + 1);
    if (!r) return NULL;
    memcpy(r, s, n);
    r[n] = '\0';
    return r;
}

static int parse_addr_kv(const char *line, const char *key, nfl_addr_t *out) {
    const char *v = find_kv(line, key);
    if (!v) return -1;
    char *t = take_token(v);
    if (!t) return -1;
    int rc = parse_addr(t, out);
    free(t);
    return rc;
}

static int parse_payload(const char *line, unsigned char **out, size_t *out_len) {
    const char *hex = find_kv(line, "hex");
    if (!hex) {
        *out = NULL;
        *out_len = 0;
        return 0;
    }
    char *t = take_token(hex);
    if (!t) return -1;
    int rc = hex_decode(t, out, out_len);
    free(t);
    return rc;
}

static bool starts_with_word(const char *line, const char *word) {
    size_t wl = strlen(word);
    return strncmp(line, word, wl) == 0 && (line[wl] == '\0' || isspace((unsigned char)line[wl]));
}

static void parse_scenario(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        char err[512];
        snprintf(err, sizeof(err), "cannot open scenario %s: %s", path, strerror(errno));
        die(err);
    }
    char *line = NULL;
    size_t cap = 0;
    int lineno = 0;
    while (getline(&line, &cap, fp) != -1) {
        lineno++;
        char *l = trim(line);
        if (*l == '\0' || *l == '#') continue;
        char err[256];
        if (starts_with_word(l, "deliver")) {
            deliver_node *n = calloc(1, sizeof(*n));
            if (!n) die("oom");
            if (parse_addr_kv(l, "to", &n->p.local_addr) ||
                parse_addr_kv(l, "from", &n->p.remote_addr) ||
                parse_payload(l, &n->p.payload, &n->p.payload_len)) {
                snprintf(err, sizeof(err), "malformed deliver at line %d", lineno);
                die(err);
            }
            *delivers_tail = n;
            delivers_tail = &n->next;
        } else if (starts_with_word(l, "expect")) {
            expect_node *n = calloc(1, sizeof(*n));
            if (!n) die("oom");
            /* "from" is the SUT-side local address, "to" is the destination. */
            if (parse_addr_kv(l, "from", &n->p.local_addr) ||
                parse_addr_kv(l, "to", &n->p.remote_addr) ||
                parse_payload(l, &n->p.payload, &n->p.payload_len)) {
                snprintf(err, sizeof(err), "malformed expect at line %d", lineno);
                die(err);
            }
            *expects_tail = n;
            expects_tail = &n->next;
        } else if (starts_with_word(l, "tcp_accept")) {
            accept_node *n = calloc(1, sizeof(*n));
            if (!n) die("oom");
            if (parse_addr_kv(l, "on", &n->local_addr) ||
                parse_addr_kv(l, "from", &n->remote_addr)) {
                snprintf(err, sizeof(err), "malformed tcp_accept at line %d", lineno);
                die(err);
            }
            *accepts_tail = n;
            accepts_tail = &n->next;
        } else if (starts_with_word(l, "tcp_connect")) {
            connect_node *n = calloc(1, sizeof(*n));
            if (!n) die("oom");
            if (parse_addr_kv(l, "to", &n->remote_addr)) {
                snprintf(err, sizeof(err), "malformed tcp_connect at line %d", lineno);
                die(err);
            }
            *connects_tail = n;
            connects_tail = &n->next;
        } else if (starts_with_word(l, "drain_sends")) {
            const char *p = l + sizeof("drain_sends") - 1;
            while (*p && isspace((unsigned char)*p)) {
                p++;
            }
            char *end = NULL;
            const long n = strtol(p, &end, 10);
            if (end == p || n < 0 || n > 1000000) {
                snprintf(err, sizeof(err), "malformed drain_sends at line %d", lineno);
                die(err);
            }
            drain_sends_remaining += (int)n;
        } else {
            snprintf(err, sizeof(err), "unknown directive at line %d: %.100s", lineno, l);
            die(err);
        }
    }
    free(line);
    fclose(fp);
}

static bool addr_eq(const nfl_addr_t *a, const nfl_addr_t *b) {
    if (a->s.sa_family != b->s.sa_family) return false;
    if (a->s.sa_family == AF_INET) {
        return a->s4.sin_port == b->s4.sin_port &&
               a->s4.sin_addr.s_addr == b->s4.sin_addr.s_addr;
    }
    if (a->s.sa_family == AF_INET6) {
        return a->s6.sin6_port == b->s6.sin6_port &&
               memcmp(&a->s6.sin6_addr, &b->s6.sin6_addr, sizeof(struct in6_addr)) == 0;
    }
    return false;
}

static bool addr_matches_bound(const nfl_addr_t *pkt_dst, const nfl_addr_t *bound) {
    if (pkt_dst->s.sa_family != bound->s.sa_family) return false;
    if (pkt_dst->s.sa_family == AF_INET) {
        const uint16_t pp = pkt_dst->s4.sin_port;
        const uint16_t bp = bound->s4.sin_port;
        /* port=0 on either side is a wildcard (ephemeral SUT-local port). */
        if (pp != 0 && bp != 0 && pp != bp) return false;
        if (bound->s4.sin_addr.s_addr == INADDR_ANY) return true;
        return pkt_dst->s4.sin_addr.s_addr == bound->s4.sin_addr.s_addr;
    }
    if (pkt_dst->s.sa_family == AF_INET6) {
        const uint16_t pp = pkt_dst->s6.sin6_port;
        const uint16_t bp = bound->s6.sin6_port;
        if (pp != 0 && bp != 0 && pp != bp) return false;
        if (IN6_IS_ADDR_UNSPECIFIED(&bound->s6.sin6_addr)) return true;
        return memcmp(&pkt_dst->s6.sin6_addr, &bound->s6.sin6_addr,
                      sizeof(struct in6_addr)) == 0;
    }
    return false;
}

static void format_addr(const nfl_addr_t *a, char *buf, size_t blen) {
    char host[64];
    if (a->s.sa_family == AF_INET) {
        inet_ntop(AF_INET, &a->s4.sin_addr, host, sizeof(host));
        snprintf(buf, blen, "%s:%u", host, ntohs(a->s4.sin_port));
    } else if (a->s.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &a->s6.sin6_addr, host, sizeof(host));
        snprintf(buf, blen, "[%s]:%u", host, ntohs(a->s6.sin6_port));
    } else {
        snprintf(buf, blen, "<af=%d>", a->s.sa_family);
    }
}

static void verify_completion(void) {
    if (expects_head) {
        fprintf(stderr, "nfl-scripted: scenario ended with unconsumed expect(s)\n");
        fflush(stderr);
        _exit(EXIT_SCENARIO_FAIL);
    }
}

int nfl_setup(void) {
    /* lo is auto-added. Add eth0 (TEST-NET-1) for non-loopback scenarios. */
    static const char eth_mac[ETHER_ADDR_LEN]     = {0x02, 0, 0, 0, 0, 0x01};
    static const char eth_brd_mac[ETHER_ADDR_LEN] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned int idx_eth = 0;
    if (nfl_add_l2_iface("eth0", IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_RUNNING,
                         1500, eth_mac, eth_brd_mac, &idx_eth) != 0) return -1;
    if (nfl_add_l3_iface_ipv4(idx_eth, "192.0.2.1", "255.255.255.0") != 0) return -1;

    const char *path = getenv("NFL_TEST_SCENARIO");
    if (!path || !*path) die("NFL_TEST_SCENARIO not set");
    parse_scenario(path);
    if (atexit(verify_completion) != 0) die("atexit failed");
    return 0;
}

bool nfl_tcp_connect(const nfl_sock_t *sock,
                     const nfl_addr_t *remote_addr) {
    (void)sock;
    connect_node **cursor = &connects_head;
    while (*cursor) {
        connect_node *q = *cursor;
        if (addr_eq(&q->remote_addr, remote_addr)) {
            *cursor = q->next;
            if (!*cursor) connects_tail = cursor;
            free(q);
            return true;
        }
        cursor = &q->next;
    }
    return false;
}

bool nfl_tcp_accept(const nfl_sock_t *sock,
                    nfl_addr_t *remote_addr) {
    accept_node **cursor = &accepts_head;
    while (*cursor) {
        accept_node *q = *cursor;
        if (addr_matches_bound(&q->local_addr, sock->local_addr)) {
            *cursor = q->next;
            if (!*cursor) accepts_tail = cursor;
            *remote_addr = q->remote_addr;
            free(q);
            return true;
        }
        cursor = &q->next;
    }
    return false;
}

nfl_conn_result nfl_send(const nfl_sock_t *sock,
                 const nfl_addr_t *to,
                 const struct iovec *iov,
                 size_t iovlen) {
    const nfl_addr_t *from = sock->local_addr;
    const ssize_t total = iov_count_bytes(iov, iovlen);
    if (total < 0) return NFL_CONN_OK;
    if (drain_sends_remaining > 0) {
        drain_sends_remaining--;
        return NFL_CONN_OK;
    }
    if (!expects_head) {
        char fbuf[80], tbuf[80], err[256];
        format_addr(from, fbuf, sizeof(fbuf));
        format_addr(to, tbuf, sizeof(tbuf));
        snprintf(err, sizeof(err),
                 "unexpected nfl_send: %s -> %s, %zd bytes (no remaining expect)",
                 fbuf, tbuf, total);
        die(err);
    }
    expect_node *e = expects_head;
    if (!addr_eq(&e->p.local_addr, from) || !addr_eq(&e->p.remote_addr, to)) {
        char fbuf[80], tbuf[80], efbuf[80], etbuf[80], err[512];
        format_addr(from, fbuf, sizeof(fbuf));
        format_addr(to, tbuf, sizeof(tbuf));
        format_addr(&e->p.local_addr, efbuf, sizeof(efbuf));
        format_addr(&e->p.remote_addr, etbuf, sizeof(etbuf));
        snprintf(err, sizeof(err),
                 "expect mismatch: got %s -> %s, want %s -> %s",
                 fbuf, tbuf, efbuf, etbuf);
        die(err);
    }
    if ((size_t)total != e->p.payload_len) {
        char err[256];
        snprintf(err, sizeof(err),
                 "expect payload size mismatch: got %zd, want %zu",
                 total, e->p.payload_len);
        die(err);
    }
    if (e->p.payload_len > 0) {
        unsigned char *flat = malloc(e->p.payload_len);
        if (!flat) die("oom");
        size_t off = 0;
        for (size_t i = 0; i < iovlen; i++) {
            memcpy(flat + off, iov[i].iov_base, iov[i].iov_len);
            off += iov[i].iov_len;
        }
        if (memcmp(flat, e->p.payload, e->p.payload_len) != 0) {
            free(flat);
            die("expect payload bytes mismatch");
        }
        free(flat);
    }
    expects_head = e->next;
    if (!expects_head) expects_tail = &expects_head;
    free(e->p.payload);
    free(e);
    return NFL_CONN_OK;
}

nfl_conn_result nfl_receive(const nfl_sock_t *sock, nfl_pkt **pkt, nfl_recv_info *info) {
    *pkt = NULL;
    if (!sock->local_addr) return NFL_CONN_OK;
    deliver_node **cursor = &delivers_head;
    while (*cursor) {
        deliver_node *q = *cursor;
        if (addr_matches_bound(&q->p.local_addr, sock->local_addr)) {
            nfl_pkt *p = nfl_alloc_pkt(q->p.payload_len);
            if (!p) return NFL_CONN_OK; // leave queued; retry next call
            if (q->p.payload_len > 0) {
                memcpy(p->buf, q->p.payload, q->p.payload_len);
            }
            *pkt = p;

            info->src_addr = q->p.remote_addr;
            info->dst_addr = q->p.local_addr;
            info->iface_index = 1;

            *cursor = q->next;
            if (!*cursor) delivers_tail = cursor;
            free(q->p.payload);
            free(q);
            return NFL_CONN_OK;
        }
        cursor = &q->next;
    }
    return NFL_CONN_OK;
}
