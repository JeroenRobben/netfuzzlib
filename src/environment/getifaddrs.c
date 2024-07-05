#include "network_env.h"
#include "interfaces.h"
#include <netfuzzlib/module_api.h>
#include <errno.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <string.h>

/**
 * Fill an ifaddrs struct (see man 3 getifaddrs) with information of an L3 network interface (nfl_l3_iface_t)
 * @param my_ifaddrs The ifaddrs struct to fill
 * @param iface_l3  The L3 network interface to use as source
 * @return -1 on error, 0 on success
 */
static int populate_ifaddrs_with_address(struct ifaddrs *my_ifaddrs, nfl_l3_iface_t *iface_l3) {
    memset(my_ifaddrs, 0, sizeof(struct ifaddrs));
    char *name = malloc(IF_NAMESIZE + 1);
    if (!name)
        return -1;

    strncpy(name, iface_l3->parent_l2_iface->name, IF_NAMESIZE);
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
        if (!IS_FLAG_SET(iface_l3->parent_l2_iface->flags, IFF_LOOPBACK)) {
            // If iface_l3 is loopback iface_l3 (e.g. 127.0.0.1) ignore netmask and return iface_l3->addr (127.0.1.1) as broadcast iface_l3, same as glibc.
            addr_v4_broadcast->sin_addr.s_addr = addr_v4->sin_addr.s_addr | (~addr_v4_netmask->sin_addr.s_addr);
        }

        my_ifaddrs->ifa_addr = (struct sockaddr *)addr_v4;
        my_ifaddrs->ifa_netmask = (struct sockaddr *)addr_v4_netmask;
        my_ifaddrs->ifa_ifu.ifu_broadaddr = (struct sockaddr *)addr_v4_broadcast;

        return 0;

    } else if (iface_l3->addr->s.sa_family == AF_INET6) {
        struct sockaddr_in6 *addr_v6 = malloc(sizeof(struct sockaddr_in6));
        if (!addr_v6) {
            free(name);
            return -1;
        }

        memcpy(addr_v6, iface_l3->addr, sizeof(struct sockaddr_in6));
        my_ifaddrs->ifa_addr = (struct sockaddr *)addr_v6;
        return 0;
    }
    __builtin_unreachable();
}

int getifaddrs_nfl(struct ifaddrs **ifap) {
    nfl_l2_iface_t *iface_l2;
    nfl_l3_iface_t *iface_l3;
    *ifap = NULL;
    struct ifaddrs *my_ifaddrs = NULL, *prev_ifaddrs = NULL;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        iface_l2 = get_l2_iface_by_index(i);
        if (!iface_l2)
            continue;
        for (iface_l3 = iface_l2->l3_interfaces; iface_l3; iface_l3 = iface_l3->next) {
            my_ifaddrs = calloc(1, sizeof(struct ifaddrs));
            if (!my_ifaddrs) {
                errno = ENOMEM;
                if (*ifap)
                    freeifaddrs(*ifap);
                return -1;
            }
            if (populate_ifaddrs_with_address(my_ifaddrs, iface_l3) != 0) {
                free(my_ifaddrs);
                if (*ifap) {
                    freeifaddrs(*ifap);
                }
                return -1;
            }
            if (prev_ifaddrs) {
                prev_ifaddrs->ifa_next = my_ifaddrs;
            } else {
                *ifap = my_ifaddrs;
            }
            prev_ifaddrs = my_ifaddrs;
        }
    }
    return 0;
}

void freeifaddrs_nfl(struct ifaddrs *ifa) {
    struct ifaddrs *addrs = ifa, *prev;
    while (addrs) {
        free(addrs->ifa_name);
        free(addrs->ifa_addr);
        if (addrs->ifa_netmask)
            free(addrs->ifa_netmask);
        if (addrs->ifa_ifu.ifu_broadaddr)
            free(addrs->ifa_ifu.ifu_broadaddr);
        prev = addrs;
        addrs = addrs->ifa_next;
        free(prev);
    }
}