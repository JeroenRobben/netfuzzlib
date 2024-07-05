#include <net/ethernet.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <assert.h>
#include "interfaces.h"
#include "netfuzzlib/log.h"
#include "sockets/network_types.h"
#include "network_env.h"
#include "sockets/sockets_util.h"
#include "netfuzzlib/util.h"

int add_loopback_device() {
    unsigned int device_index = 0;
    char mac_lo[ETHER_ADDR_LEN] = {};
    char mac_lo_broadcast[ETHER_ADDR_LEN] = {};
    nfl_add_l2_iface("lo", 73, 65536, mac_lo, mac_lo_broadcast, &device_index);
    if (!device_index) {
        nfl_log_error("Could not add loopback device during environment initialization");
        return -1;
    }
    int err = nfl_add_l3_iface_ipv4(device_index, "127.0.0.1", "255.0.0.0");
    if (err) {
        nfl_log_error("Could not init loopback device ipv4 during environment initialization");
    }
    err = nfl_add_l3_iface_ipv6(device_index, "::1", 128, 0x10);
    if (err) {
        nfl_log_error("Could not init loopback device ipv6 during environment initialization");
    }
    return err;
}

int nfl_add_l2_iface(const char *name, short flags, int mtu, const char *hw_addr, const char *hw_broadcast_addr, unsigned int *device_index) {
    nfl_l2_iface_t *l2_iface = NULL;
    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = &get_network_env()->l2_interfaces[i];
        if (l2_iface->index)
            continue;
        l2_iface->index = i;
        *device_index = i;
        break;
    }
    if (!l2_iface) {
        errno = ENOBUFS;
        return -1;
    }

    strncpy(l2_iface->name, name, IF_NAMESIZE);
    l2_iface->flags = flags;
    l2_iface->mtu = mtu;
    memcpy(l2_iface->hw_addr, hw_addr, ETHER_ADDR_LEN);
    memcpy(l2_iface->hw_broadcast_addr, hw_broadcast_addr, ETHER_ADDR_LEN);
    nfl_log_debug("Added network l2_iface: %s, index: %d", network_device_to_string(l2_iface), l2_iface->index);
    return 0;
}

int nfl_add_l3_iface_ipv4(unsigned int device_index, const char *addr_text, const char *netmask_text) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(device_index);
    if (!l2_iface) {
        return -1;
    }
    nfl_l3_iface_t *device_address = calloc(1, sizeof(nfl_l3_iface_t));
    if (!device_address) {
        errno = ENOBUFS;
        return -1;
    }
    nfl_addr_t *addr = calloc(1, sizeof(nfl_addr_t));
    if (!addr) {
        free(device_address);
        errno = ENOBUFS;
        return -1;
    }
    nfl_addr_t *netmask = calloc(1, sizeof(struct sockaddr_in));
    if (!netmask) {
        free(device_address);
        free(addr);
        errno = ENOBUFS;
        return -1;
    }

    addr->s4.sin_family = AF_INET;
    if (!inet_aton(addr_text, &addr->s4.sin_addr)) {
        free(device_address);
        free(addr);
        free(netmask);
        errno = EINVAL;
        return -1;
    }

    netmask->s4.sin_family = AF_INET;
    if (!inet_aton(netmask_text, &netmask->s4.sin_addr)) {
        free(device_address);
        free(addr);
        free(netmask);
        errno = EINVAL;
        return -1;
    }

    device_address->addr = addr;
    device_address->netmask = netmask;

    add_l3_iface_to_l2_iface(l2_iface, device_address);
    nfl_log_debug("Added network address: %s", network_device_address_to_string(device_address));
    return 0;
}

int nfl_add_l3_iface_ipv6(unsigned int device_index, const char *addr_text, int prefix_length, uint32_t scope) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(device_index);
    if (!l2_iface) {
        return -1;
    }
    nfl_l3_iface_t *l3_iface = calloc(1, sizeof(nfl_l3_iface_t));
    if (!l3_iface) {
        errno = ENOBUFS;
        return -1;
    }

    nfl_addr_t *addr = calloc(1, sizeof(nfl_addr_t));
    if (!addr) {
        free(l3_iface);
        errno = ENOBUFS;
        return -1;
    }

    addr->s6.sin6_family = AF_INET6;
    addr->s6.sin6_scope_id = scope;
    if (inet_pton(AF_INET6, addr_text, &addr->s6.sin6_addr) == -1) {
        free(l3_iface);
        free(addr);
        return -1;
    }
    l3_iface->addr = addr;
    l3_iface->prefix = prefix_length;

    add_l3_iface_to_l2_iface(l2_iface, l3_iface);
    nfl_log_debug("Added network address: %s", network_device_address_to_string(l3_iface));
    return 0;
}

void add_l3_iface_to_l2_iface(nfl_l2_iface_t *l2_iface, nfl_l3_iface_t *l3_iface) {
    l3_iface->parent_l2_iface = l2_iface;
    l3_iface->next = l2_iface->l3_interfaces;
    l2_iface->l3_interfaces = l3_iface;
}

nfl_l2_iface_t *get_l2_iface_by_index(unsigned int index) {
    if (index == 0)
        return NULL;
    nfl_l2_iface_t *device = &get_network_env()->l2_interfaces[index];
    if (device->index != index)
        return NULL;
    return device;
}

nfl_l2_iface_t *get_l2_iface_by_name(const char *name) {
    if (!name)
        return NULL;

    nfl_l2_iface_t *l2_iface;
    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = get_l2_iface_by_index(i);
        if (!l2_iface)
            continue;
        if (strncmp(l2_iface->name, name, IFNAMSIZ) == 0)
            return l2_iface;
    }
    return NULL;
}

void get_l3_iface_broadcast_addr(const nfl_l3_iface_t *l3_iface, struct sockaddr_in *broadcast) {
    assert(l3_iface->addr->s.sa_family == AF_INET);
    memset(broadcast, 0, sizeof(struct sockaddr_in));
    broadcast->sin_family = AF_INET;
    broadcast->sin_addr.s_addr = l3_iface->addr->s4.sin_addr.s_addr | ~l3_iface->netmask->s4.sin_addr.s_addr;
}

static bool can_bind_ipv4_addr(const struct sockaddr_in *addr_v4) {
    nfl_l2_iface_t *l2_iface;
    nfl_l3_iface_t *l3_iface;

    if (addr_is_zero_address((nfl_addr_t *)addr_v4))
        return true;
    if (addr_v4->sin_addr.s_addr == htonl(INADDR_BROADCAST))
        return true;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = get_l2_iface_by_index(i);
        if (!l2_iface)
            continue;
        for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
            if (l3_iface->addr->s.sa_family != AF_INET)
                continue;
            if (((struct sockaddr_in *)l3_iface->addr)->sin_addr.s_addr == addr_v4->sin_addr.s_addr)
                return true;
        }
    }
    return false;
}

static bool can_bind_ipv6_addr(const struct sockaddr_in6 *addr_v6) {
    nfl_l2_iface_t *l2_iface;
    nfl_l3_iface_t *l3_iface;

    if (addr_is_zero_address((nfl_addr_t *)addr_v6))
        return true;
    if (IN6_IS_ADDR_LOOPBACK(&addr_v6->sin6_addr) || IN6_IS_ADDR_MULTICAST(&addr_v6->sin6_addr))
        return true;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        l2_iface = get_l2_iface_by_index(i);
        if (!l2_iface)
            continue;
        for (l3_iface = l2_iface->l3_interfaces; l3_iface; l3_iface = l3_iface->next) {
            if (l3_iface->addr->s.sa_family != AF_INET6)
                continue;
            if (memcmp(&addr_v6->sin6_addr, &l3_iface->addr->s6.sin6_addr, sizeof(struct in6_addr)) == 0)
                return true;
        }
    }
    return false;
}

bool can_bind_to_address(nfl_sock_t *sock, const nfl_addr_t *addr) {
    if (addr->s.sa_family == AF_INET && sock->domain == AF_INET) {
        return can_bind_ipv4_addr(&addr->s4);
    } else if (addr->s.sa_family == AF_INET6 && sock->domain == AF_INET6) {
        return can_bind_ipv6_addr(&addr->s6);
    } else if (addr->s.sa_family == AF_NETLINK && sock->domain == AF_NETLINK) {
        return true;
    }
    return false;
}

int get_l3_iface_ipv4_count() {
    nfl_l3_iface_t *iface_l3;
    nfl_l2_iface_t *iface_l2;
    int count = 0;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        iface_l2 = get_l2_iface_by_index(i);
        if (!iface_l2)
            continue;
        for (iface_l3 = iface_l2->l3_interfaces; iface_l3; iface_l3 = iface_l3->next) {
            if (iface_l3->addr->s.sa_family == AF_INET) {
                count++;
            }
        }
    }
    return count;
}

bool l2_iface_is_loopback(nfl_l2_iface_t *l2_iface) {
    return strncmp(l2_iface->name, "lo", IFNAMSIZ);
}

unsigned int if_nametoindex_nfl(const char *name) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_name(name);
    if (!l2_iface) {
        nfl_log_info("if_nametoindex called for unknown interface: %s", name);
        errno = EINVAL;
        return -1;
    }
    return l2_iface->index;
}

char *if_indextoname_nfl(unsigned int index, char *ifname) {
    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(index);
    if (!l2_iface) {
        nfl_log_info("if_indextoname called for unknown index: %d", index);
        errno = EINVAL;
        return NULL;
    }
    strcpy(ifname, l2_iface->name);
    return ifname;
}