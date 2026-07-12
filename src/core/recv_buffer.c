#include "recv_buffer.h"

#include <stdio.h>
#include <stdlib.h>

#include "network_types.h"
#include <netinet/in.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <string.h>
#include <netfuzzlib/callbacks.h>
#include <netfuzzlib/api.h>
#include "network_env.h"
#include "fd_table.h"
#include "handlers.h"
#include <sys/epoll.h>

void sock_readiness_changed(nfl_sock_full_t *sock) {
    sock->ready_seq++;
}

void sock_append_packet(nfl_sock_full_t *socket, nfl_recv_pkt *packet) {
    nfl_recv_pkt **packet_ll_ptr;
    for (packet_ll_ptr = &socket->packets_ll; (*packet_ll_ptr); packet_ll_ptr = &(*packet_ll_ptr)->next) {
        ;
    }
    *packet_ll_ptr = packet;
    sock_readiness_changed(socket);
}

void sock_clear_recv_buffer_and_load_next_packet(nfl_sock_full_t *socket) {
    if (!socket || !socket->packets_ll) {
        return;
    }
    nfl_recv_pkt *packet = socket->packets_ll;
    socket->packets_ll = packet->next;
    socket->packet_offset = 0;
    nfl_free_pkt(packet);
}

static void query_module_for_packet(nfl_sock_full_t *sock) {
    nfl_pkt *mpkt = NULL;
    nfl_recv_info info;
    memset(&info, 0, sizeof(info));

    const nfl_conn_result r = nfl_receive((const nfl_sock_t *)sock, &mpkt, &info);
    if (r == NFL_CONN_CLOSED) {
        sock->shutdown_read = true;
        sock_readiness_changed(sock);
        return;
    }
    if (!mpkt) {
        return; 
    }

    nfl_recv_pkt *pkt = calloc(1, sizeof(nfl_recv_pkt));
    if (!pkt) {
        free(mpkt->buf);
        free(mpkt);
        return;
    }
    pkt->buf = mpkt->buf;
    pkt->len = mpkt->len;
    free(mpkt);

    pkt->remote_addr = info.src_addr;
    if (info.dst_addr.s.sa_family != 0) {
        pkt->local_addr = info.dst_addr;
    } else if (sock->local_addr) {
        pkt->local_addr = *sock->local_addr;
    }
    pkt->device_index = info.iface_index ? info.iface_index : 1;
    sock_append_packet(sock, pkt);
}

void sock_update_recv_buffer(nfl_sock_full_t *sock) {
    const nfl_recv_pkt *packet = sock->packets_ll;
    if (packet && sock->packet_offset < packet->len) {
        return; // A packet is loaded and not yet fully read.
    }
    if (packet && sock->packet_offset == packet->len) { // The current packet has been fully read, get the next one
        sock_clear_recv_buffer_and_load_next_packet(sock);
    }
    if (!sock->packets_ll) { // Current recv buffer is empty, query the fuzzing module for a new packet
        if (sock->domain == AF_NETLINK) {
            return;
        }
        query_module_for_packet(sock);
    }
}

ssize_t socket_recv_iov(nfl_sock_full_t *sock, const struct iovec *dst_iov_array, const size_t dst_iov_array_len, const bool peek) {
    sock_update_recv_buffer(sock);
    if (!sock->packets_ll) {
        nfl_log("Failed to receive data, no incoming data available: %s", sock_to_str(sock));
        return 0;
    }

    const bool is_stream = (sock->type == SOCK_STREAM);
    ssize_t total_bytes_read = 0;
    nfl_recv_pkt *pkt = sock->packets_ll;
    size_t pkt_off = sock->packet_offset;

    for (size_t i = 0; i < dst_iov_array_len && pkt; i++) {
        const struct iovec *dst_iov = &dst_iov_array[i];
        char *iov_buf = dst_iov->iov_base;
        size_t iov_off = 0;

        while (iov_off < dst_iov->iov_len && pkt) {
            const char *pkt_buf = pkt->buf;
            while (pkt_off < pkt->len && iov_off < dst_iov->iov_len) {
                iov_buf[iov_off++] = pkt_buf[pkt_off++];
                total_bytes_read++;
            }
            if (pkt_off >= pkt->len) {
                if (!is_stream) {
                    pkt = NULL; 
                    break;
                }
                pkt = pkt->next;
                pkt_off = 0;
            }
        }
    }

    if (!peek) {
        if (is_stream) {
            while (sock->packets_ll && sock->packets_ll != pkt) {
                nfl_recv_pkt *consumed = sock->packets_ll;
                sock->packets_ll = consumed->next;
                nfl_free_pkt(consumed);
            }
            sock->packet_offset = pkt ? pkt_off : 0;
        } else {
            sock->packet_offset = pkt_off;
        }
    }
    nfl_log("Read %zd bytes: %s", total_bytes_read, sock_to_str(sock));
    return total_bytes_read;
}

nfl_pkt *nfl_alloc_pkt(const size_t len_bytes) {
    void *buf = calloc(1, len_bytes);
    if (!buf) {
        return NULL;
    }
    nfl_pkt *packet = calloc(1, sizeof(nfl_pkt));
    if (!packet) {
        free(buf);
        return NULL;
    }

    packet->buf = buf;
    packet->len = len_bytes;
    return packet;
}

nfl_recv_pkt *alloc_recv_pkt(const size_t len_bytes) {
    void *buf = calloc(1, len_bytes);
    if (!buf) {
        return NULL;
    }
    nfl_recv_pkt *packet = calloc(1, sizeof(nfl_recv_pkt));
    if (!packet) {
        free(buf);
        return NULL;
    }

    packet->buf = buf;
    packet->len = len_bytes;
    return packet;
}

void nfl_free_pkt(nfl_recv_pkt *packet) {
    free(packet->buf);
    free(packet);
}

void free_packet_ll(nfl_recv_pkt *packet) {
    while (packet) {
        nfl_recv_pkt *next = packet->next;
        nfl_free_pkt(packet);
        packet = next;
    }
}

size_t sock_recv_buffer_bytes_available(nfl_sock_full_t *sock) {
    sock_update_recv_buffer(sock);
    if (!sock->packets_ll) {
        return 0;
    }
    return sock->packets_ll->len - sock->packet_offset;
}

bool nfl_all_sockets_in_process_idle(void) {
    for (int i = 0; i < NFL_FD_TABLE_SIZE; i++) {
        nfl_sock_full_t *sock = get_nfl_sock(i);
        if (!sock || sock->kind == NFL_FD_EPOLL) {
            continue;
        }
        if (nfl_sock_poll(sock, EPOLLIN)) {
            return false;
        }
    }
    return true;
}

char *network_device_to_string(const nfl_l2_iface_t *device, char *buf, const size_t len) {
    snprintf(buf, len,
             "Network device name: %s, index: %d, flags: %d, mtu: %d, "
             "hw_addr: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX, "
             "hw_broadcast_addr: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
             device->name, device->index, device->flags, device->mtu, device->hw_addr[0], device->hw_addr[1], device->hw_addr[2], device->hw_addr[3],
             device->hw_addr[4], device->hw_addr[5], device->hw_broadcast_addr[0], device->hw_broadcast_addr[1], device->hw_broadcast_addr[2],
             device->hw_broadcast_addr[3], device->hw_broadcast_addr[4], device->hw_broadcast_addr[5]);
    return buf;
}

char *network_device_address_to_string(const nfl_l3_iface_t *address, char *buf, const size_t len) {
    char addr_str[INET6_ADDRSTRLEN];
    char netmask_str[INET_ADDRSTRLEN];

    switch (address->addr->s.sa_family) {
    case (AF_INET): {
        inet_ntop(AF_INET, &address->addr->s4.sin_addr, addr_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct sockaddr_in *)address->netmask)->sin_addr, netmask_str, INET_ADDRSTRLEN);
        snprintf(buf, len, "IPV4 address: %s, netmask: %s, parent device: %s", addr_str, netmask_str, address->parent_l2_iface->name);
        break;
    }
    case (AF_INET6): {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)address->addr)->sin6_addr, addr_str, INET6_ADDRSTRLEN);
        snprintf(buf, len, "IPV6 address: %s, prefix: %d, parent device: %s", addr_str, address->prefix, address->parent_l2_iface->name);
        break;
    }
    default: {
        nfl_die(1, "network_device_address_to_string, invalid address domain, code should not be reachable");
    }
    }
    return buf;
}

bool ipv4_addr_within_subnet(const struct in_addr *network, const struct in_addr *netmask, const struct in_addr *addr) {
    return (network->s_addr & netmask->s_addr) == (addr->s_addr & netmask->s_addr);
}

bool ipv6_addr_within_subnet(const struct in6_addr *network, const unsigned int prefix, const struct in6_addr *addr) {
    int network_bits_to_check = (int)prefix;
    for (int i = 0; i < 16; i++) {
        if (network_bits_to_check <= 0) {
            return true;
        }
        uint8_t network_mask = network->s6_addr[i];
        uint8_t addr_mask = addr->s6_addr[i];
        const int bits_to_skip = network_bits_to_check < 8 ? 8 - network_bits_to_check : 0;
        network_mask >>= bits_to_skip;
        addr_mask >>= bits_to_skip;
        if (network_mask != addr_mask) {
            return false;
        }
        network_bits_to_check -= 8;
    }
    return true;
}

char *sock_to_str(const struct nfl_sock_full_t *sock) {
    static _Thread_local char output[200];
    const char *domain;
    const char *type;
    const char *protocol;

    char local_addr_str[SOCKADDR_STR_MAX_LEN] = "Not set";
    char remote_addr_str[SOCKADDR_STR_MAX_LEN] = "Not set";
    if (sock->local_addr) {
        sockaddr_to_str(sock->local_addr, local_addr_str, sizeof(local_addr_str));
    }
    if (sock->remote_addr) {
        sockaddr_to_str(sock->remote_addr, remote_addr_str, sizeof(remote_addr_str));
    }

    switch (sock->domain) {
    case (AF_INET):
        domain = "IPv4";
        break;
    case (AF_INET6):
        domain = "IPv6";
        break;
    case (AF_NETLINK):
        domain = "Netlink";
        break;
    default:
        domain = "Unknown";
    }
    switch (sock->type) {
    case (SOCK_STREAM):
        type = "STREAM";
        break;
    case (SOCK_DGRAM):
        type = "DGRAM";
        break;
    case (SOCK_RAW):
        type = "RAW";
        break;
    default:
        type = "Unknown";
    }
    switch (sock->protocol) {
    case (IPPROTO_TCP):
        protocol = "TCP";
        break;
    case (IPPROTO_UDP):
        protocol = "UDP";
        break;
    case (NETLINK_ROUTE):
        protocol = "RTNetlink";
        break;
    case (IPPROTO_ICMP):
        protocol = "ICMPv4";
        break;
    case (IPPROTO_ICMPV6):
        protocol = "ICMPv6";
        break;
    default:
        protocol = "Unknown";
    }

    snprintf(output, sizeof(output), "socket: %s %s %s | local_addr_str: %s | remote_addr_str: %s", domain, type, protocol, local_addr_str, remote_addr_str);

    return output;
}

char *sockaddr_to_str_static_alloc(const nfl_addr_t *addr) {
    static _Thread_local char output[SOCKADDR_STR_MAX_LEN] = { 0 };
    sockaddr_to_str(addr, output, sizeof(output));
    return output;
}

char *sockaddr_to_str(const nfl_addr_t *addr, char *buf, const size_t len) {
    memset(buf, 0, len);
    if (addr->s.sa_family == AF_INET) {
        inet_ntop(AF_INET, &addr->s4.sin_addr, buf, len);
        const size_t bytes_left = len - strlen(buf) - sizeof('\0');
        snprintf(buf + strlen(buf), bytes_left, ":%d", ntohs(addr->s4.sin_port));
    } else if (addr->s.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr->s6.sin6_addr, buf, len);
        const size_t bytes_left = len - strlen(buf) - sizeof('\0');
        snprintf(buf + strlen(buf), bytes_left, "|:%d", ntohs(addr->s6.sin6_port));
    } else if (addr->s.sa_family == AF_NETLINK) {
        snprintf(buf, len, "Netlink");
    } else {
        snprintf(buf, len, "Unknown");
    }
    buf[len - 1] = '\0';
    return buf;
}
