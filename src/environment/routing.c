#include <stdlib.h>
#include <arpa/inet.h>
#include <errno.h>
#include "routing.h"
#include "network_env.h"
#include "sockets/sockets_util.h"
#include "interfaces.h"

int nfl_set_ipv4_default_gateway(const char *gateway_addr_text, unsigned int device_index) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(device_index);
    if (!l2_iface) {
        nfl_log_warn("Could not find l2_iface with index: %d, not setting ipv4 default gateway", device_index);
        return -1;
    }
    ipv4_default_gateway *ipv4_gateway = calloc(1, sizeof(ipv4_default_gateway));
    if (!ipv4_gateway) {
        errno = ENOBUFS;
        nfl_log_error("Out of heap space, not setting ipv4 default gateway", device_index);
        return -1;
    }
    int ret = inet_pton(AF_INET, gateway_addr_text, &ipv4_gateway->gateway_addr);
    if (ret != 1) {
        nfl_log_warn("Could not parse ipv4 address: %s, not setting ipv4 default gateway", gateway_addr_text);
    }

    nfl_l3_iface_t *l3_iface;
    for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
        if (l3_iface->addr->s.sa_family != AF_INET)
            continue;

        if (ipv4_addr_within_subnet(&l3_iface->addr->s4.sin_addr, &l3_iface->netmask->s4.sin_addr, &ipv4_gateway->gateway_addr)) {
            ipv4_gateway->interface = l3_iface;
            break;
        }
    }
    if (!ipv4_gateway->interface) {
        nfl_log_warn("Default gateway address %s was not within subnet of ipv4 interface of l2_iface %s with index %d, not setting ipv4 default gateway",
                     gateway_addr_text, l2_iface->name, device_index);
        return -1;
    }

    if (get_network_env()->ipv4_gateway) {
        free(get_network_env()->ipv4_gateway);
    }
    get_network_env()->ipv4_gateway = ipv4_gateway;
    nfl_log_info("Default IPv4 gateway set to %s | l2_iface %s", gateway_addr_text, ipv4_gateway->interface->parent_l2_iface->name);
    return 0;
}

int nfl_set_ipv6_default_gateway(const char *gateway_addr_text, unsigned int device_index) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(device_index);
    if (!l2_iface) {
        nfl_log_warn("Could not find l2_iface with index: %d, not setting ipv6 default gateway", device_index);
        return -1;
    }
    ipv6_default_gateway *ipv6_gateway = calloc(1, sizeof(ipv6_default_gateway));
    if (!ipv6_gateway) {
        errno = ENOBUFS;
        nfl_log_error("Out of heap space, not setting ipv6 default gateway", device_index);
        return -1;
    }
    int ret = inet_pton(AF_INET6, gateway_addr_text, &ipv6_gateway->gateway_addr);
    if (ret != 1) {
        nfl_log_warn("Could not parse ipv6 address: %s, not setting ipv6 default gateway", gateway_addr_text);
    }

    nfl_l3_iface_t *l3_iface;
    for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
        if (l3_iface->addr->s.sa_family != AF_INET6)
            continue;
        if (ipv6_addr_within_subnet(&l3_iface->addr->s6.sin6_addr, l3_iface->prefix, &ipv6_gateway->gateway_addr)) {
            ipv6_gateway->interface = l3_iface;
            break;
        }
    }
    if (!ipv6_gateway->interface) {
        nfl_log_warn("Default gateway address %s was not within subnet of ipv6 interface of l2_iface %s with index %d, not setting ipv4 default gateway",
                     gateway_addr_text, l2_iface->name, device_index);
        return -1;
    }

    if (get_network_env()->ipv6_gateway) {
        free(get_network_env()->ipv6_gateway);
    }
    get_network_env()->ipv6_gateway = ipv6_gateway;
    nfl_log_info("Default IPv6 gateway set to %s | l2_iface %s", gateway_addr_text, ipv6_gateway->interface->parent_l2_iface->name);
    return 0;
}

/**
 * Get the local interface which would be used for sending a packet to a given destination
 * @param dest_addr The destination address of the packet
 * @return A pointer to the nfl_l3_iface_t which would be used as outgoing interface for the packet, or NULL if no route to dest_addr exists
 */
nfl_l3_iface_t *routing_table_lookup_ipv4(const struct in_addr *dest_addr) {
    //First check local subnets, otherwise return default gateway
    nfl_l2_iface_t *l2_iface;
    nfl_l3_iface_t *l3_iface;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = get_l2_iface_by_index(i);
        if (!l2_iface)
            continue;
        for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
            if (l3_iface->addr->s.sa_family != AF_INET)
                continue;
            if (ipv4_addr_within_subnet(&l3_iface->addr->s4.sin_addr, &l3_iface->netmask->s4.sin_addr, dest_addr)) {
                return l3_iface;
            }
        }
    }
    if (get_network_env()->ipv4_gateway) {
        return get_network_env()->ipv4_gateway->interface;
    }
    return NULL;
}

/**
 * Get the local interface which would be used for sending a packet to a given destination
 * @param dest_addr The destination address of the packet
 * @return A pointer to the nfl_l3_iface_t which would be used as outgoing interface for the packet, or NULL if no route to dest_addr exists
 */
nfl_l3_iface_t *routing_table_lookup_ipv6(const struct in6_addr *dest_addr) {
    //First check local subnets, otherwise return default gateway
    nfl_l2_iface_t *l2_iface;
    nfl_l3_iface_t *l3_iface;
    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = get_l2_iface_by_index(i);
        if (!l2_iface)
            continue;
        for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
            if (l3_iface->addr->s.sa_family != AF_INET6)
                continue;
            if (ipv6_addr_within_subnet(&l3_iface->addr->s6.sin6_addr, l3_iface->prefix, dest_addr)) {
                return l3_iface;
            }
        }
    }
    if (get_network_env()->ipv6_gateway) {
        return get_network_env()->ipv6_gateway->interface;
    }
    return NULL;
}

nfl_l3_iface_t *routing_table_lookup(const nfl_addr_t *dest_addr) {
    nfl_l3_iface_t *result;
    switch (dest_addr->s.sa_family) {
    case AF_INET: {
        result = routing_table_lookup_ipv4(&dest_addr->s4.sin_addr);
        break;
    }
    case AF_INET6: {
        result = routing_table_lookup_ipv6(&dest_addr->s6.sin6_addr);
        break;
    }
    default:
        nfl_exit_log(1, "Invalid address family in routing_table_lookup");
    }
    if (!result) {
        nfl_log_warn("Routing table lookup failed: could not find device that can reach %s", sockaddr_to_str_static_alloc(dest_addr));
    }
    return result;
}
