#include "ioctl.h"
#include "interfaces.h"
#include "recv_buffer.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <net/if_arp.h>
#include <string.h>
#include <sys/ioctl.h>

/* Macro: warn, set errno, return -1. */
#define IOCTL_FAIL(err, msg)         \
    do {                             \
        nfl_log("ioctl: " msg); \
        errno = (err);               \
        return -1;                   \
    } while (0)

/**
 * Handle a SIOCGIFCONF ioctl request
 * @param my_ifconf The ifconf struct to fill
 * @return 0 on success, -1 on error
 */
static int handle_siocgifconf(struct ifconf *my_ifconf) {
    int l3_ipv4_ifaces_count = get_l3_iface_ipv4_count(); // Only returns IPV4 l3_interfaces
    const int ifc_len_required = (int)sizeof(struct ifreq) * l3_ipv4_ifaces_count;

    if (my_ifconf->ifc_req == NULL) {
        my_ifconf->ifc_len = ifc_len_required;
        return 0;
    }
    if (ifc_len_required > my_ifconf->ifc_len) {
        l3_ipv4_ifaces_count = my_ifconf->ifc_len / ((int)sizeof(struct ifreq));
    }

    my_ifconf->ifc_len = l3_ipv4_ifaces_count * ((int)sizeof(struct ifreq));

    int count = 0;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *iface_l2 = get_l2_iface_by_index(i);
        if (!iface_l2) {
            continue;
        }
        for (const nfl_l3_iface_t *iface_l3 = iface_l2->l3_interfaces; iface_l3; iface_l3 = iface_l3->next) {
            if (iface_l3->addr->s.sa_family != AF_INET) {
                continue;
            }
            snprintf(my_ifconf->ifc_req[count].ifr_name, IFNAMSIZ, "%s", iface_l2->name);
            memcpy(&my_ifconf->ifc_req[count].ifr_addr, iface_l3->addr, sizeof(struct sockaddr_in));
            count++;
            if (count >= l3_ipv4_ifaces_count) {
                break;
            }
        }
    }
    return 0;
}

/*
 * See man 7 netdevice
 */
int ioctl_nfl(nfl_sock_full_t *sock, const unsigned long request, void *argp) {
    if (!argp) {
        errno = EFAULT;
        return -1;
    }
    switch (request) {
    case SIOCGIFCONF:
        return handle_siocgifconf((struct ifconf *)argp);
    case FIONREAD:
        *((int *)argp) = (int)sock_recv_buffer_bytes_available(sock);
        return 0;
    case FIONBIO: {
        const int *non_blocking = (int *)argp;
        sock->status_flags.blocking = !(*non_blocking);
        return 0;
    }
    case FIOCLEX:
    case FIONCLEX:
        return 0;
    default:
        break;
    }

    struct ifreq *my_ifreq = (struct ifreq *)argp;

    nfl_l2_iface_t *l2_iface = request == SIOCGIFNAME ? get_l2_iface_by_index(my_ifreq->ifr_ifindex) : get_l2_iface_by_name(my_ifreq->ifr_name);

    if (!l2_iface) {
        errno = ENODEV;
        return -1;
    }

    switch (request) {
    case SIOCGIFNAME: // get l2_iface name
        snprintf(my_ifreq->ifr_name, IFNAMSIZ, "%s", l2_iface->name);
        return 0;
    case SIOCGIFINDEX: // get l2_iface index
        my_ifreq->ifr_ifindex = (int)l2_iface->index;
        return 0;
    case SIOCGIFFLAGS: // get flags
        my_ifreq->ifr_flags = l2_iface->flags;
        return 0;
    case SIOCGIFPFLAGS:
        my_ifreq->ifr_flags = 0;
        return 0;
    case SIOCGIFADDR: { // ipv4 only!
        const nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                memcpy(&my_ifreq->ifr_addr, l3_iface->addr, sizeof(struct sockaddr_in));
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        errno = EADDRNOTAVAIL;
        return -1;
    }
    case SIOCGIFHWADDR:
        memset(&my_ifreq->ifr_hwaddr, 0, sizeof(struct sockaddr));
        my_ifreq->ifr_hwaddr.sa_family = (l2_iface->flags & IFF_LOOPBACK) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        memcpy(my_ifreq->ifr_hwaddr.sa_data, l2_iface->hw_addr, ETHER_ADDR_LEN);
        return 0;

    case SIOCGIFBRDADDR: {
        const nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                get_l3_iface_broadcast_addr(l3_iface, (struct sockaddr_in *)&my_ifreq->ifr_broadaddr);
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        errno = EADDRNOTAVAIL;
        return -1;
    }

    case SIOCGIFNETMASK: {
        const nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                memcpy(&my_ifreq->ifr_netmask, l3_iface->netmask, sizeof(struct sockaddr_in));
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        errno = EADDRNOTAVAIL;
        return -1;
    }
    case SIOCGIFMTU:
        my_ifreq->ifr_mtu = l2_iface->mtu;
        return 0;
    case SIOCGIFTXQLEN:
        my_ifreq->ifr_qlen = 1000;
        return 0;
    case SIOCGIFMAP:
        nfl_log("Ioctl requesting getting l2_iface hardware params (SIOCGIFMAP), return dummy value");
        memset(&my_ifreq->ifr_map, 0, sizeof(struct ifmap));
        return 0;
    case SIOCGIFMETRIC:
        nfl_log("Ioctl requesting getting l2_iface metric (SIOCGIFMETRIC), silent ignore, return 0 as metric, same behaviour as glibc");
        my_ifreq->ifr_metric = 0;
        return 0;
    case SIOCSIFMETRIC:
        IOCTL_FAIL(EOPNOTSUPP, "SIOCSIFMETRIC: setting metric not supported");
    case SIOCSIFFLAGS:
        IOCTL_FAIL(EPERM, "SIOCSIFFLAGS: setting interface flags not permitted");
    case SIOCSIFPFLAGS:
        IOCTL_FAIL(EPERM, "SIOCSIFPFLAGS: setting extended flags not permitted");
    case SIOCSIFADDR:
        IOCTL_FAIL(EPERM, "SIOCSIFADDR: setting interface address not permitted");
    case SIOCDIFADDR:
        IOCTL_FAIL(EPERM, "SIOCDIFADDR: deleting interface address not permitted");
    case SIOCGIFDSTADDR:
        IOCTL_FAIL(EOPNOTSUPP, "SIOCGIFDSTADDR: point-to-point not supported");
    case SIOCSIFDSTADDR:
        IOCTL_FAIL(EPERM, "SIOCSIFDSTADDR: setting peer address not permitted");
    case SIOCSIFHWADDR:
        IOCTL_FAIL(EPERM, "SIOCSIFHWADDR: setting hardware address not permitted");
    case SIOCSIFBRDADDR:
        IOCTL_FAIL(EPERM, "SIOCSIFBRDADDR: setting broadcast address not permitted");
    case SIOCSIFNETMASK:
        IOCTL_FAIL(EPERM, "SIOCSIFNETMASK: setting netmask not permitted");
    case SIOCSIFMTU:
        IOCTL_FAIL(EPERM, "SIOCSIFMTU: setting MTU not permitted");
    case SIOCSIFHWBROADCAST:
        IOCTL_FAIL(EPERM, "SIOCSIFHWBROADCAST: setting hw broadcast not permitted");
    case SIOCSIFMAP:
        IOCTL_FAIL(EPERM, "SIOCSIFMAP: setting hardware params not permitted");
    case SIOCADDMULTI:
        IOCTL_FAIL(EPERM, "SIOCADDMULTI: adding multicast filter not permitted");
    case SIOCDELMULTI:
        IOCTL_FAIL(EPERM, "SIOCDELMULTI: deleting multicast filter not permitted");
    case SIOCSIFTXQLEN:
        IOCTL_FAIL(EPERM, "SIOCSIFTXQLEN: setting TX queue length not permitted");
    case SIOCSIFNAME:
        IOCTL_FAIL(EPERM, "SIOCSIFNAME: renaming interface not permitted");
    default:
        errno = EINVAL;
        return -1;
    }
}
