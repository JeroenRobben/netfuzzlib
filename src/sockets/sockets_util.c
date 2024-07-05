#include "sockets_util.h"
#include "network_types.h"
#include <netinet/in.h>
#include <linux/netlink.h>
#include <arpa/inet.h>
#include <string.h>
#include <netfuzzlib/module_api.h>
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include "environment/fd_table.h"

void sock_append_packet(nfl_sock_t *socket, nfl_pkt *packet) {
    nfl_pkt **packet_ll_ptr;
    for (packet_ll_ptr = &socket->packets_ll; (*packet_ll_ptr); packet_ll_ptr = &(*packet_ll_ptr)->next)
        ;
    *packet_ll_ptr = packet;
}

void sock_clear_recv_buffer_and_load_next_packet(nfl_sock_t *socket) {
    if (!socket || !socket->packets_ll)
        return;
    nfl_pkt *packet = socket->packets_ll;
    socket->packets_ll = packet->next;
    socket->packet_offset = 0;
    nfl_free_packet(packet);
}

void sock_update_recv_buffer(nfl_sock_t *sock) {
    nfl_pkt *packet = sock->packets_ll;
    if (packet && sock->packet_offset < packet->iov.iov_len) {
        return; // All good, a packet has been loaded and is not yet fully read;
    }
    if (packet && sock->packet_offset == packet->iov.iov_len) { //The current packet has been fully read, get the next one
        sock_clear_recv_buffer_and_load_next_packet(sock);
    }
    if (!sock->packets_ll) { //Current recv buffer is empty, query the fuzzing module for a new packet
        if (sock->domain == AF_NETLINK) {
            return;
        }
        nfl_pkt *module_packet = nfl_receive((const nfl_sock_module_t *)sock, sock->local_addr);
        if (module_packet)
            sock_append_packet(sock, module_packet);
    }
}

ssize_t socket_recv_iov(nfl_sock_t *sock, struct iovec *dst_iov_array, size_t dst_iov_array_len, bool peek) {
    sock_update_recv_buffer(sock);
    if (!sock->packets_ll) {
        nfl_log_info("Failed to receive data, no incoming data available: %s", sock_to_str(sock));
        return 0;
    }

    ssize_t total_bytes_read = 0;
    size_t dst_iov_array_offset;

    struct iovec *dst_iov;
    size_t dst_iov_offset;

    char *socket_buf = sock->packets_ll->iov.iov_base;
    size_t socket_buf_offset = sock->packet_offset;

    //Iterate over the given array of iov's (dst_iov_array)
    for (dst_iov_array_offset = 0; dst_iov_array_offset < dst_iov_array_len; dst_iov_array_offset++) {
        dst_iov = &dst_iov_array[dst_iov_array_offset];
        char *iov_buf = dst_iov->iov_base;
        dst_iov_offset = 0;

        //Copy data from the sock buffer to the current iovec iov_buf, until either all bytes in the current packet are copied or iov_buf is full.
        while ((socket_buf_offset < sock->packets_ll->iov.iov_len) && (dst_iov_offset < dst_iov->iov_len)) {
            iov_buf[dst_iov_offset] = socket_buf[socket_buf_offset];
            dst_iov_offset++;
            socket_buf_offset++;
            total_bytes_read++;
        }
    }
    if (!peek)
        sock->packet_offset = socket_buf_offset;
    nfl_log_info("Read %d bytes: %s", total_bytes_read, sock_to_str(sock));
    return total_bytes_read;
}

nfl_pkt *nfl_alloc_pkt(size_t len_bytes) {
    void *buf = calloc(1, len_bytes);
    if (!buf)
        return NULL;
    nfl_pkt *packet = calloc(1, sizeof(nfl_pkt));
    if (!packet) {
        free(buf);
        return NULL;
    }

    packet->iov.iov_base = buf;
    packet->iov.iov_len = len_bytes;
    return packet;
}

void nfl_free_packet(nfl_pkt *packet) {
    if (get_network_env()->enable_packet_free) {
        free(packet->iov.iov_base);
        free(packet);
    }
}

void free_packet_ll(nfl_pkt *packet) {
    if (get_network_env()->enable_packet_free) {
        nfl_pkt *next;
        while (packet) {
            next = packet->next;
            nfl_free_packet(packet);
            packet = next;
        }
    }
}

size_t sock_recv_buffer_bytes_available(nfl_sock_t *sock) {
    sock_update_recv_buffer(sock);
    if (!sock->packets_ll) {
        return 0;
    }
    return sock->packets_ll->iov.iov_len - sock->packet_offset;
}

bool all_packets_consumed() {
    for (int i = 0; i <= SOCKET_FD_MAX; i++) {
        nfl_sock_t *sock = get_nfl_sock(i);
        if (!sock)
            continue;
        if (sock_recv_buffer_bytes_available(sock) > 0)
            return false;
    }
    return true;
}

char *network_device_to_string(nfl_l2_iface_t *device) {
    static char response[200];
    snprintf(response, sizeof(response),
             "Network device name: %s, index: %d, flags: %d, mtu: %d, "
             "hw_addr: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX, "
             "hw_broadcast_addr: %02hhX:%02hhX:%02hhX:%02hhX:%02hhX:%02hhX",
             device->name, device->index, device->flags, device->mtu, device->hw_addr[0], device->hw_addr[1], device->hw_addr[2], device->hw_addr[3],
             device->hw_addr[4], device->hw_addr[5], device->hw_broadcast_addr[0], device->hw_broadcast_addr[1], device->hw_broadcast_addr[2],
             device->hw_broadcast_addr[3], device->hw_broadcast_addr[4], device->hw_broadcast_addr[5]);
    return response;
}

char *network_device_address_to_string(nfl_l3_iface_t *address) {
    static char response[200];
    char addr_str[INET6_ADDRSTRLEN];
    char netmask_str[INET_ADDRSTRLEN];

    switch (address->addr->s.sa_family) {
    case (AF_INET): {
        inet_ntop(AF_INET, &address->addr->s4.sin_addr, addr_str, INET6_ADDRSTRLEN);
        inet_ntop(AF_INET, &((struct sockaddr_in *)address->netmask)->sin_addr, netmask_str, INET_ADDRSTRLEN);
        snprintf(response, sizeof(response), "IPV4 address: %s, netmask: %s, parent device: %s", addr_str, netmask_str, address->parent_l2_iface->name);
        break;
    }
    case (AF_INET6): {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)address->addr)->sin6_addr, addr_str, INET6_ADDRSTRLEN);
        snprintf(response, sizeof(response), "IPV6 address: %s, prefix: %d, parent device: %s", addr_str, address->prefix, address->parent_l2_iface->name);
        break;
    }
    default: {
        nfl_exit_log(1, "network_device_address_to_string, invalid address domain, code should not be reachable");
    }
    }
    return response;
}

bool ipv4_addr_within_subnet(const struct in_addr *network, const struct in_addr *netmask, const struct in_addr *addr) {
    return (network->s_addr & netmask->s_addr) == (addr->s_addr & netmask->s_addr);
}

bool ipv6_addr_within_subnet(const struct in6_addr *network, unsigned int prefix, const struct in6_addr *addr) {
    addr->s6_addr;
    int network_bits_to_check = prefix;
    for (int i = 0; i < 16; i++) {
        if (network_bits_to_check <= 0)
            return true;
        uint8_t network_mask = network->s6_addr[i];
        uint8_t addr_mask = addr->s6_addr[i];
        int bits_to_skip = network_bits_to_check < 8 ? 8 - network_bits_to_check : 0;
        network_mask >>= bits_to_skip;
        addr_mask >>= bits_to_skip;
        if (network_mask != addr_mask)
            return false;
        network_bits_to_check -= 8;
    }
    return true; //TODO
}

char *sock_to_str(const struct nfl_sock_t *sock) {
    static char output[200];
    const char *domain, *type, *protocol;

    char local_addr_str[SOCKADDR_STR_MAX_LEN] = "Not set";
    char remote_addr_str[SOCKADDR_STR_MAX_LEN] = "Not set";
    if (sock->local_addr)
        sockaddr_to_str(sock->local_addr, local_addr_str, sizeof(local_addr_str));
    if (sock->remote_addr)
        sockaddr_to_str(sock->remote_addr, remote_addr_str, sizeof(remote_addr_str));

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

//
////Return true if an address lies in the subnet of an interface, false otherwise
//bool address_in_interface_subnet(klee_network_device_address * interface, struct sockaddr * addr) {
//  if(interface->addr->sa_family != addr->sa_family) {
//    return false;
//  }
//  if(addr->sa_family == AF_INET) {
//    in_addr_t interface_ip = ((struct sockaddr_in *)interface->addr)->sin_addr.s_addr;
//    in_addr_t mask = ((struct sockaddr_in *)interface->netmask)->sin_addr.s_addr;
//    in_addr_t addr_ip = ((struct sockaddr_in *)addr)->sin_addr.s_addr;
//    return ((interface_ip & mask) == (addr_ip & mask));
//  }
//  else if(addr->sa_family == AF_INET6) {
//    //todo
//    return false;
//  }
//  return false;
//}

//
////Return the interface for which some given address lies in its subnet.
////Returns NULL if no such interface is found.
//klee_network_device_address * get_interface_in_subnet(struct sockaddr * addr) {
//  unsigned int device_index;
//  for(device_index = 0; device_index < get_network_env()->devices_len; device_index++) {
//    klee_network_device * device = &get_network_env()->devices_ll[device_index];
//    klee_network_device_address * interface = device->interfaces;
//    while(interface) {
//      if(address_in_interface_subnet(interface, addr)) {
//        return interface;
//      }
//      interface = interface->next;
//    }
//  }
//  return NULL;
//}

char *sockaddr_to_str_static_alloc(const nfl_addr_t *addr) {
    static char output[SOCKADDR_STR_MAX_LEN];
    memset(output, 0, SOCKADDR_STR_MAX_LEN);
    sockaddr_to_str(addr, output, sizeof(output));
    return output;
}

char *sockaddr_to_str(const nfl_addr_t *addr, char *buf, size_t len) {
    memset(buf, 0, len);
    if (addr->s.sa_family == AF_INET) {
        inet_ntop(AF_INET, &addr->s4.sin_addr, buf, len);
        size_t bytes_left = len - strlen(buf) - sizeof('\0');
        snprintf(buf + strlen(buf), bytes_left, ":%d", ntohs(addr->s4.sin_port));
    } else if (addr->s.sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &addr->s6.sin6_addr, buf, len);
        size_t bytes_left = len - strlen(buf) - sizeof('\0');
        snprintf(buf + strlen(buf), bytes_left, "|:%d", ntohs(addr->s6.sin6_port));
    } else if (addr->s.sa_family == AF_NETLINK) {
        snprintf(buf, len, "Netlink");
    } else {
        snprintf(buf, len, "Unknown");
    }
    buf[len - 1] = '\0';
    return buf;
}