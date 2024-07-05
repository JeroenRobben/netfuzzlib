#ifndef NETFUZZLIB_NETWORK_TYPES_H
#define NETFUZZLIB_NETWORK_TYPES_H

#include <net/if.h>
#include <stdbool.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netfuzzlib/api.h>

#define MAX_L2_INTERFACES 20
#define SOCKET_FD_START 70 // int value of the first socket file descriptor that will be used for sockets.
#define SOCKET_FD_MAX 1024 // Highest possible socket file descriptor
#define IS_FLAG_SET(flags, flag) ((flags) & (flag))

#define IP_OPTIONS_LEN_MAX 40

typedef struct nfl_status_flags_t {
    bool recv_pkt_info; // True iff recvpktinfo option is set
    bool blocking; // True iff this is a blocking socket
    int rcvtimeo; // The timeout for receiving data
    int sndtimeo; // The timeout for sending data
    int tcp_fastopen; // The TCP_FASTOPEN option
    socklen_t ip_options_len;
    char ip_options[40]; // The IP_OPTIONS option
} nfl_status_flags_t;

/*
 * Holds information about an open socket fd
 */
typedef struct nfl_sock_t {
    int domain; // Network domain of the socket, see AF_INET*
    int type; // Socket type, see SOCK_*
    int protocol; // Socket protocol, see IPPROTO*

    nfl_addr_t *local_addr; // The local endpoint of this socket
    nfl_addr_t *remote_addr; // The remote endpoint of this socket

    struct nfl_status_flags_t status_flags;

    bool shutdown_read; // True iff this socket has been closed for reads
    bool shutdown_write; // True iff this socket has been closed for writes
    bool is_listening; // True iff this socket is listening for incoming stream
            // connections. Has no meaning if this socket is not of
            // type SOCK_STREAM

    struct nfl_pkt *packets_ll; //Buffer of currently received network data
    size_t packet_offset; //The offset in the packet buffer

    int references; // Amount of references in file descriptor table to the socket

    struct nfl_sock_t *tcp_pending; // The pending tcp connection, if any
} nfl_sock_t;

/*
 * Holds information about an L3 interface
 */
typedef struct nfl_l3_iface_t {
    struct nfl_l3_iface_t *next;
    struct nfl_l2_iface_t *parent_l2_iface;
    nfl_addr_t *addr; /* Address */
    union { /* Netmask or prefix length */
        unsigned int prefix;
        nfl_addr_t *netmask;
    };
} nfl_l3_iface_t;

/*
 * Holds information about a network device / L2 interface
 */
typedef struct nfl_l2_iface_t {
    char name[IF_NAMESIZE + 1]; /* Name of device */
    short flags; /* Flags from SIOCGIFFLAGS */
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

/*
 * Wrapper type holding the current network environment.
 * Holds all network l2_interfaces and open sockets
 */
typedef struct network_env {
    ipv4_default_gateway *ipv4_gateway;
    ipv6_default_gateway *ipv6_gateway;
    bool enable_packet_free;
    nfl_sock_t *fd_table[SOCKET_FD_MAX + 1];
    nfl_l2_iface_t l2_interfaces[MAX_L2_INTERFACES];
    int fd_dev_null;
} network_env;

#endif // NETFUZZLIB_NETWORK_TYPES_H
