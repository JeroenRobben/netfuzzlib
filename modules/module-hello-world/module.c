#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netfuzzlib/module_api.h>
#include "hooks/models.h"
#include "netfuzzlib/util.h"

#define HELLO_WORLD_MSG "Hello world\r\n"

/**
 * Initialize this module, called once during environment setup.
 * Usually adding network interfaces happens here.
 */
int nfl_initialize() {
    unsigned int device_index = 0;
    char mac_eth0[ETHER_ADDR_LEN] = { '\x01', '\x02', '\x03', '\x04', '\x05', '\x06' };
    char mac_eth0_brd[ETHER_ADDR_LEN] = { '\xff', '\xff', '\xff', '\xff', '\xff', '\xff' };
    nfl_add_l2_iface("not-a-real-eth0", IFF_MULTICAST | IFF_UP, 65536, mac_eth0, mac_eth0_brd, &device_index);
    nfl_add_l3_iface_ipv4(device_index, "1.2.3.4", "255.255.255.255");
    nfl_add_l3_iface_ipv6(device_index, "::1234", 128, 0x20);
    return 0;
}

/**
 * Define whether an attempted outgoing tcp connection should succeed
 * Parameters local_addr and remote_addr are guaranteed t  connection.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_connect(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, const nfl_addr_t *remote_addr) {
    return true;
}

/**
 * Define an incoming tcp connection. Called when an application invokes 'accept' on a listening socket.
 * Parameters local_addr and remote_addr are guaranteed to be of same type, sockaddr_in or sockaddr_in6
 * @param local_addr The local address bound to the socket.
 * @param remote_addr The address of the remote endpoint. This must be initialized by the module in case the connection was successful.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_accept(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, nfl_addr_t *remote_addr) {
    static int amount_incoming_connections_left = 10;
    if (amount_incoming_connections_left <= 0)
        return false;

    amount_incoming_connections_left--;
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

/**
 * Called when an application attempts to send data on a network socket
 * @param sock The socket on which a send call was issued
 * @param from The sender address of the packet, type sockaddr_in | sockaddr_in6
 * @param to The destination address of the packet, type sockaddr_in | sockaddr_in6
 * @param iov Array of iovec structs containing the outgoing data
 * @param iovlen The amount of iovec structs in the array
 * @return The amount of bytes sent, or a negative value in case of an error
 */
ssize_t nfl_send(const nfl_sock_module_t *sock, const nfl_addr_t *from, const nfl_addr_t *to, struct iovec *iov, size_t iovlen) {
    return iov_count_bytes(iov, iovlen);
}

/**
 * Called when an application attempts to read data on a network sock, and the current buffer is empty
 * @param sock The sock on which a read call was issued
 * @param bound_addr The address bound to the sock, type sockaddr_in | sockaddr_in6
 * @param packet Packet which must be allocated and initialized by the network environment, see nfl_alloc_pkt() in module_provided.h
 *               Must remain unaltered if no packet has been received.
 *               For TCP only the iov field needs to be filled in, other fields are ignored.
 */
nfl_pkt *nfl_receive(const nfl_sock_module_t *sock, const nfl_addr_t *bound_addr) {
    static int amount_packets_left = 10;
    if (amount_packets_left <= 0) {
        if (sock->protocol == IPPROTO_TCP) {
            shutdown_nfl((nfl_sock_t *)sock, SHUT_RDWR);
        }
        return NULL;
    }
    amount_packets_left--;
    nfl_pkt *packet = nfl_alloc_pkt(sizeof(HELLO_WORLD_MSG));
    if (!packet) {
        return NULL;
    }
    strcpy(packet->iov.iov_base, HELLO_WORLD_MSG);

    packet->device_index = 1;
    if (sock->domain == AF_INET) {
        inet_pton(AF_INET, "127.0.0.1", &packet->local_addr.s4.sin_addr);
        inet_pton(AF_INET, "127.0.0.1", &packet->remote_addr.s4.sin_addr);

        packet->local_addr.s4.sin_family = packet->remote_addr.s4.sin_family = AF_INET;
        packet->local_addr.s4.sin_port = bound_addr->s4.sin_port;
        packet->remote_addr.s4.sin_port = htons(9999);
        return packet;
    } else if (sock->domain == AF_INET6) {
        inet_pton(AF_INET6, "::1", &packet->local_addr.s6.sin6_addr);
        inet_pton(AF_INET6, "::1", &packet->remote_addr.s6.sin6_addr);

        packet->local_addr.s6.sin6_family = packet->remote_addr.s6.sin6_family = AF_INET6;
        packet->local_addr.s6.sin6_port = bound_addr->s6.sin6_port;
        packet->remote_addr.s6.sin6_port = htons(9999);
        return packet;
    }
    return NULL;
}
