#ifndef NETFUZZLIB_TYPES_H
#define NETFUZZLIB_TYPES_H
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/netlink.h>

typedef union {
    struct sockaddr s;
    struct sockaddr_in s4;
    struct sockaddr_in6 s6;
    struct sockaddr_nl nl;
} nfl_addr_t;

/**
 * A network packet
 */
typedef struct nfl_pkt {
    struct iovec iov; // Iovec structure representing the contents of this packet.

    unsigned int device_index; // The index of the device by which this packet was received. Ignored for TCP packets.
    nfl_addr_t local_addr; // The receiver address of this packet, e.g. 255.255.255.255. Ignored for TCP packets.
    nfl_addr_t remote_addr; // The sender address of this packet, e.g. 255.255.255.255. Ignored for TCP packets.
    struct nfl_pkt *next;
} nfl_pkt;

typedef struct nfl_sock_module_t {
    int domain; // Network domain of the socket, AF_INET | AF_INET6
    int type; // Socket type, SOCK_DGRAM | SOCK_STREAM | SOCK_RAW
    int protocol; // Socket protocol, IPPROTO_UDP | IPPROTO_TCP | IPPROTO_ICMP | IPPROTO_ICMPV6
} nfl_sock_module_t;

#endif //NETFUZZLIB_TYPES_H
