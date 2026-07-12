#ifndef NETFUZZLIB_NETWORK_TYPES_H
#define NETFUZZLIB_NETWORK_TYPES_H

#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/time.h>
#include <netfuzzlib/api.h>

enum {
    NFL_RESERVED_FD_START = 1000,
    NFL_RESERVED_FD_MODULE_START = NFL_RESERVED_FD_START + 2,
    NFL_RESERVED_FD_MAX = 65535,
};

enum {
    MAX_L2_INTERFACES = 20,
    SOCKET_FD_START = 70,
    NFL_FD_TABLE_SIZE = NFL_RESERVED_FD_START,
    IP_OPTIONS_LEN_MAX = 40,
};

typedef struct nfl_status_flags_t {
    bool recv_pkt_info;      // True if recvpktinfo option is set
    bool blocking;           // True if this is a blocking socket
    bool v6only;             // True if SUT set IPV6_V6ONLY=1
    struct timeval rcvtimeo; // SO_RCVTIMEO
    struct timeval sndtimeo; // SO_SNDTIMEO
    int tcp_fastopen;        // TCP_FASTOPEN option
    socklen_t ip_options_len;
    char ip_options[40]; // IP_OPTIONS option
} nfl_status_flags_t;

/* The recv(2) flag bits the internal receive path acts on, decoded once from
 * the raw `int flags` at the entry point (recv_flags_decode in core.c).
 * MSG_OOB / MSG_ERRQUEUE are rejected there and never reach here. Effective
 * blocking is `sock->status_flags.blocking && !msg_dontwait`. */
typedef struct nfl_recv_flags {
    bool msg_dontwait; // MSG_DONTWAIT: this call must not block
    bool msg_peek;     // MSG_PEEK: read without consuming
    bool msg_trunc;    // MSG_TRUNC: report the true length, not the copied count
} nfl_recv_flags;

struct nfl_sock_full_t;
struct nfl_epoll_t;

typedef enum nfl_fd_kind {
    NFL_FD_SOCKET = 0, /* calloc default */
    NFL_FD_EPOLL,
} nfl_fd_kind;

typedef struct nfl_epoll_watch_t {
    struct nfl_epoll_t *owner;      /* interest set holding this watch */
    struct nfl_sock_full_t *target;      /* watched description */
    struct nfl_epoll_watch_t *prev; /* links on target->watch_list */
    struct nfl_epoll_watch_t *next;

    int fd;          /* lookup key only; never resolved back to a socket */
    uint32_t events; /* requested mask, incl. EPOLLET / EPOLLONESHOT */
    uint64_t data;   /* opaque data echoed back to the caller */

    uint32_t last_revents; /* EPOLLET: mask already reported to the caller */
    uint64_t last_seq;     /* EPOLLET: target->ready_seq at that report */
    bool disarmed;         /* EPOLLONESHOT: fired, awaiting EPOLL_CTL_MOD */
} nfl_epoll_watch_t;

typedef struct nfl_epoll_t {
    nfl_epoll_watch_t **watches; /* pointers to stable, individually owned nodes */
    size_t n_watches;
    size_t cap;
    size_t rr_cursor;     /* nfl watch index the next scan starts at */
    bool rr_native_first; /* which source gets served first this round */
    int native_epfd;      /* -1 until a native fd is registered */
    int create_flags;     /* epoll_create1 flags, for the deferred creation */
    size_t n_native_watches;
} nfl_epoll_t;

typedef struct nfl_recv_pkt {
    void *buf;                 // Owned packet bytes.
    size_t len;                // Number of bytes in buf.
    unsigned int device_index; // Receiving interface. Ignored for TCP.
    nfl_addr_t local_addr;     // Destination address. Ignored for TCP.
    nfl_addr_t remote_addr;    // Source address. Ignored for TCP.
    struct nfl_recv_pkt *next;
} nfl_recv_pkt;

typedef struct nfl_sock_full_t {
    int domain;   // Network domain of the socket, see AF_INET*
    int type;     // Socket type, see SOCK_*
    int protocol; // Socket protocol, see IPPROTO*

    nfl_addr_t *local_addr;  // The local endpoint of this socket
    nfl_addr_t *remote_addr; // The remote endpoint of this socket

    struct nfl_status_flags_t status_flags;

    bool shutdown_read;  // True if this socket has been closed for reads
    bool shutdown_write; // True if this socket has been closed for writes
    bool is_listening;   // True if this socket is listening for incoming stream
                         // connections. Has no meaning if this socket is not of
                         // type SOCK_STREAM

    struct nfl_recv_pkt *packets_ll; // Buffer of currently received network data
    size_t packet_offset;       // The offset in the packet buffer

    bool recv_gap_pending;

    int references; // Amount of references in file descriptor table to the socket

    struct nfl_sock_full_t *tcp_pending; // The pending tcp connection, if any

    nfl_epoll_t *epoll_data;
    nfl_epoll_watch_t *watch_list;
    uint64_t ready_seq;
 
    int idle_polls;

    nfl_fd_kind kind;

    bool stdio_has_pushback;
    unsigned char stdio_pushback;
} nfl_sock_full_t;

/**
 * Holds information about an L3 interface
 */
typedef struct nfl_l3_iface_t {
    struct nfl_l3_iface_t *next;
    struct nfl_l2_iface_t *parent_l2_iface;
    nfl_addr_t *addr; /* Address */
    union {           /* Netmask or prefix length */
        unsigned int prefix;
        nfl_addr_t *netmask;
    };
} nfl_l3_iface_t;

/**
 * Holds information about a network device / L2 interface
 */
typedef struct nfl_l2_iface_t {
    char name[IF_NAMESIZE + 1]; /* Name of device */
    short flags;                /* Flags from SIOCGIFFLAGS */
    unsigned int index;
    char hw_addr[ETHER_ADDR_LEN];
    char hw_broadcast_addr[ETHER_ADDR_LEN];
    int mtu;
    nfl_l3_iface_t *l3_interfaces;
} nfl_l2_iface_t;

typedef struct ipv4_default_gateway {
    struct in_addr gateway_addr;
    nfl_l3_iface_t *interface;
} ipv4_default_gateway;

typedef struct ipv6_default_gateway {
    struct in6_addr gateway_addr;
    nfl_l3_iface_t *interface;
} ipv6_default_gateway;

/**
 * Wrapper type holding the current network environment.
 * Holds all network l2_interfaces and open sockets
 */
typedef struct network_env {
    ipv4_default_gateway *ipv4_gateway;
    ipv6_default_gateway *ipv6_gateway;
    nfl_sock_full_t *fd_table[NFL_FD_TABLE_SIZE];
    bool fd_in_pool[NFL_FD_TABLE_SIZE];
    nfl_l2_iface_t l2_interfaces[MAX_L2_INTERFACES];
    int fd_dev_null;
} network_env;

#endif // NETFUZZLIB_NETWORK_TYPES_H
