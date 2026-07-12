#ifndef NETFUZZLIB_TYPES_H
#define NETFUZZLIB_TYPES_H
#include <stddef.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>

typedef union {
    struct sockaddr s;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_nl nl;
} nfl_addr_t;

typedef struct nfl_pkt {
    void *buf;
    size_t len;
} nfl_pkt;

//You only need to fill this in for UDP packets. dst_addr and iface_index are optional.
typedef struct nfl_recv_info {
    nfl_addr_t src_addr;      // Sender address/port
    nfl_addr_t dst_addr;      // Destination address/port. You only need to fill this in for targets that use IP_PKTINFO, e.g. to know the destination IP of a packet received on a socket bound to 0.0.0.0.
    unsigned int iface_index; // Receiving interface index. You only need to fill this in for targets that use IP_PKTINFO, e.g. to know which interface a packet was received on. Use the same interface indexing as given by ip addr.
} nfl_recv_info;

typedef struct nfl_sock_t {
    int domain;   // Network domain, AF_INET or AF_INET6.
    int type;     // Socket type, SOCK_DGRAM, SOCK_STREAM or SOCK_RAW.
    int protocol; // Protocol, IPPROTO_UDP, IPPROTO_TCP, IPPROTO_ICMP or IPPROTO_ICMPV6.
    const nfl_addr_t *local_addr;  // Local endpoint, NULL if unbound.
    const nfl_addr_t *remote_addr; // Connected peer, NULL if not connected.
} nfl_sock_t;

#endif // NETFUZZLIB_TYPES_H
