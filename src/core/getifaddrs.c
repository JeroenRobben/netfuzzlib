#include "network_env.h"
#include "interfaces.h"
#include "getifaddrs.h"
#include <netfuzzlib/callbacks.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>

/* Build an IPv6 netmask sockaddr from a prefix length (1..128). */
static void prefix_to_in6_netmask(unsigned int prefix, struct in6_addr *netmask) {
    memset(netmask, 0, sizeof(*netmask));
    if (prefix > 128) {
        prefix = 128;
    }
    for (unsigned int i = 0; i < prefix; i++) {
        netmask->s6_addr[i / 8] |= (uint8_t)(1U << (7 - (i % 8)));
    }
}

/**
 * Fill an ifaddrs struct (see man 3 getifaddrs) with information of an L3 network interface (nfl_l3_iface_t)
 * @param my_ifaddrs The ifaddrs struct to fill
 * @param iface_l3  The L3 network interface to use as source
 * @return -1 on error, 0 on success
 */
static int populate_ifaddrs_with_address(struct ifaddrs *my_ifaddrs, const nfl_l3_iface_t *iface_l3) {
    memset(my_ifaddrs, 0, sizeof(struct ifaddrs));
    char *name = malloc(IF_NAMESIZE + 1);
    if (!name) {
        return -1;
    }

    strncpy(name, iface_l3->parent_l2_iface->name, IF_NAMESIZE);
    name[IF_NAMESIZE] = '\0';
    my_ifaddrs->ifa_name = name;
    my_ifaddrs->ifa_flags = iface_l3->parent_l2_iface->flags;

    if (iface_l3->addr->s.sa_family == AF_INET) {
        struct sockaddr_in *addr_v4 = malloc(sizeof(struct sockaddr_in));
        if (!addr_v4) {
            free(name);
            return -1;
        }
        struct sockaddr_in *addr_v4_netmask = malloc(sizeof(struct sockaddr_in));
        if (!addr_v4_netmask) {
            free(name);
            free(addr_v4);
            return -1;
        }
        struct sockaddr_in *addr_v4_broadcast = malloc(sizeof(struct sockaddr_in));
        if (!addr_v4_broadcast) {
            free(name);
            free(addr_v4);
            free(addr_v4_netmask);
            return -1;
        }

        memcpy(addr_v4, iface_l3->addr, sizeof(struct sockaddr_in));
        memcpy(addr_v4_netmask, iface_l3->netmask, sizeof(struct sockaddr_in));
        memcpy(addr_v4_broadcast, iface_l3->addr, sizeof(struct sockaddr_in));
        if (!(iface_l3->parent_l2_iface->flags & IFF_LOOPBACK)) {
            // If iface_l3 is loopback iface_l3 (e.g. 127.0.0.1) ignore netmask and return iface_l3->addr (127.0.1.1) as broadcast iface_l3, same as glibc.
            addr_v4_broadcast->sin_addr.s_addr = addr_v4->sin_addr.s_addr | (~addr_v4_netmask->sin_addr.s_addr);
        }

        my_ifaddrs->ifa_addr = (struct sockaddr *)addr_v4;
        my_ifaddrs->ifa_netmask = (struct sockaddr *)addr_v4_netmask;
        my_ifaddrs->ifa_ifu.ifu_broadaddr = (struct sockaddr *)addr_v4_broadcast;
        return 0;
    }
    if (iface_l3->addr->s.sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_v6 = malloc(sizeof(struct sockaddr_in6));
        if (!addr_v6) {
            free(name);
            return -1;
        }
        struct sockaddr_in6 *netmask_v6 = malloc(sizeof(struct sockaddr_in6));
        if (!netmask_v6) {
            free(name);
            free(addr_v6);
            return -1;
        }
        memcpy(addr_v6, iface_l3->addr, sizeof(struct sockaddr_in6));
        memset(netmask_v6, 0, sizeof(*netmask_v6));
        netmask_v6->sin6_family = AF_INET6;
        prefix_to_in6_netmask(iface_l3->prefix, &netmask_v6->sin6_addr);

        my_ifaddrs->ifa_addr = (struct sockaddr *)addr_v6;
        my_ifaddrs->ifa_netmask = (struct sockaddr *)netmask_v6;
        return 0;
    }
    __builtin_unreachable();
}

// Build the AF_PACKET (link-layer) ifaddrs entry that glibc emits per interface.
static struct ifaddrs *populate_packet_ifaddrs(const nfl_l2_iface_t *iface_l2) {
    struct ifaddrs *my_ifaddrs = calloc(1, sizeof(struct ifaddrs));
    if (!my_ifaddrs) {
        return NULL;
    }
    char *name = malloc(IF_NAMESIZE + 1);
    if (!name) {
        free(my_ifaddrs);
        return NULL;
    }
    struct sockaddr_ll *ll = calloc(1, sizeof(struct sockaddr_ll));
    if (!ll) {
        free(name);
        free(my_ifaddrs);
        return NULL;
    }
    strncpy(name, iface_l2->name, IF_NAMESIZE);
    name[IF_NAMESIZE] = '\0';

    ll->sll_family = AF_PACKET;
    ll->sll_ifindex = (int)iface_l2->index;
    ll->sll_hatype = (iface_l2->flags & IFF_LOOPBACK) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
    ll->sll_halen = ETHER_ADDR_LEN;
    memcpy(ll->sll_addr, iface_l2->hw_addr, ETHER_ADDR_LEN);

    my_ifaddrs->ifa_name = name;
    my_ifaddrs->ifa_flags = iface_l2->flags;
    my_ifaddrs->ifa_addr = (struct sockaddr *)ll;
    return my_ifaddrs;
}

int getifaddrs_nfl(struct ifaddrs **ifap) {
    *ifap = NULL;
    struct ifaddrs *prev_ifaddrs = NULL;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *iface_l2 = get_l2_iface_by_index(i);
        if (!iface_l2) {
            continue;
        }

        // glibc emits the AF_PACKET (link-layer) entry first, then AF_INET/INET6.
        struct ifaddrs *packet_entry = populate_packet_ifaddrs(iface_l2);
        if (!packet_entry) {
            errno = ENOMEM;
            if (*ifap) {
                freeifaddrs(*ifap);
            }
            return -1;
        }
        if (prev_ifaddrs) {
            prev_ifaddrs->ifa_next = packet_entry;
        } else {
            *ifap = packet_entry;
        }
        prev_ifaddrs = packet_entry;

        for (nfl_l3_iface_t *iface_l3 = iface_l2->l3_interfaces; iface_l3; iface_l3 = iface_l3->next) {
            struct ifaddrs *my_ifaddrs = calloc(1, sizeof(struct ifaddrs));
            if (!my_ifaddrs) {
                errno = ENOMEM;
                if (*ifap) {
                    freeifaddrs(*ifap);
                }
                return -1;
            }
            if (populate_ifaddrs_with_address(my_ifaddrs, iface_l3) != 0) {
                free(my_ifaddrs);
                if (*ifap) {
                    freeifaddrs(*ifap);
                }
                return -1;
            }
            prev_ifaddrs->ifa_next = my_ifaddrs;
            prev_ifaddrs = my_ifaddrs;
        }
    }
    return 0;
}

void freeifaddrs_nfl(struct ifaddrs *ifa) {
    struct ifaddrs *addrs = ifa;
    while (addrs) {
        free(addrs->ifa_name);
        free(addrs->ifa_addr);
        if (addrs->ifa_netmask) {
            free(addrs->ifa_netmask);
        }
        if (addrs->ifa_ifu.ifu_broadaddr) {
            free(addrs->ifa_ifu.ifu_broadaddr);
        }
        struct ifaddrs *prev = addrs;
        addrs = addrs->ifa_next;
        free(prev);
    }
}
