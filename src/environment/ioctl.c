#include "hooks/hooks.h"
#include "sockets/sockets_util.h"
#include "interfaces.h"
#include <arpa/inet.h>
#include <errno.h>
#include <net/if_arp.h>
#include <string.h>
#include <sys/ioctl.h>

#define IOCTL_CASE(request, msg, ret) \
    case ((request)):                 \
        nfl_log_warn("ioctl: " msg);  \
        return (ret);                 \
        break

/**
 * Handle a SIOCGIFCONF ioctl request
 * @param my_ifconf The ifconf struct to fill
 * @return 0 on success, -1 on error
 */
static int handle_siocgifconf(struct ifconf *my_ifconf) {
    int l3_ipv4_ifaces_count = get_l3_iface_ipv4_count(); // Only returns IPV4 l3_interfaces
    int ifc_len_required = (int)sizeof(struct ifreq) * l3_ipv4_ifaces_count;

    if (my_ifconf->ifc_req == NULL) {
        my_ifconf->ifc_len = ifc_len_required;
        return 0;
    }
    if (ifc_len_required > my_ifconf->ifc_len) {
        l3_ipv4_ifaces_count = my_ifconf->ifc_len / ((int)sizeof(struct ifreq));
    }

    my_ifconf->ifc_len = l3_ipv4_ifaces_count * ((int)sizeof(struct ifreq));

    nfl_l2_iface_t *iface_l2;
    nfl_l3_iface_t *iface_l3;

    int count = 0;

    for (int i = 1; i < MAX_L2_INTERFACES; i++) {
        iface_l2 = get_l2_iface_by_index(i);
        if (!iface_l2)
            continue;
        for (iface_l3 = iface_l2->l3_interfaces; iface_l3; iface_l3 = iface_l3->next) {
            if (iface_l3->addr->s.sa_family != AF_INET)
                continue;
            strcpy(my_ifconf->ifc_req[count].ifr_name, iface_l2->name);
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
int ioctl_nfl(nfl_sock_t *sock, unsigned long request, void *argp) {
    if (!argp)
        return -EINVAL;
    switch (request) {
    case SIOCGIFCONF:
        return handle_siocgifconf((struct ifconf *)argp);
    case FIONREAD:
        *((int *)argp) = (int)sock_recv_buffer_bytes_available(sock);
        return 0;
    case FIONBIO: {
        int *non_blocking = (int *)argp;
        sock->status_flags.blocking = !(*non_blocking);
        return 0;
    }
    case FIOCLEX:
    case FIONCLEX:
        return 0;
    }

    struct ifreq *my_ifreq = (struct ifreq *)argp;

    nfl_l2_iface_t *l2_iface = request == SIOCGIFNAME ? get_l2_iface_by_index(my_ifreq->ifr_ifindex) : get_l2_iface_by_name(my_ifreq->ifr_name);

    if (!l2_iface) {
        return -EINVAL;
    }

    switch (request) {
    case SIOCGIFNAME: // get l2_iface name
        strcpy(my_ifreq->ifr_name, l2_iface->name);
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
        nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                memcpy(&my_ifreq->ifr_addr, l3_iface->addr, sizeof(struct sockaddr_in));
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        return -EINVAL;
    }
    case SIOCGIFHWADDR:
        memset(&my_ifreq->ifr_hwaddr, 0, sizeof(struct sockaddr));
        my_ifreq->ifr_hwaddr.sa_family = IS_FLAG_SET(l2_iface->flags, IFF_LOOPBACK) ? ARPHRD_LOOPBACK : ARPHRD_ETHER;
        memcpy(my_ifreq->ifr_hwaddr.sa_data, l2_iface->hw_addr, ETHER_ADDR_LEN);
        return 0;

    case SIOCGIFBRDADDR: {
        nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                get_l3_iface_broadcast_addr(l3_iface, (struct sockaddr_in *)&my_ifreq->ifr_broadaddr);
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        return -EINVAL;
    }

    case SIOCGIFNETMASK: {
        nfl_l3_iface_t *l3_iface = l2_iface->l3_interfaces;
        while (l3_iface) {
            if (l3_iface->addr->s.sa_family == AF_INET) {
                memcpy(&my_ifreq->ifr_netmask, l3_iface->netmask, sizeof(struct sockaddr_in));
                return 0;
            }
            l3_iface = l3_iface->next;
        }
        return -EINVAL;
    }
    case SIOCGIFMTU:
        my_ifreq->ifr_mtu = l2_iface->mtu;
        return 0;
    case SIOCGIFTXQLEN:
        my_ifreq->ifr_qlen = 1000;
        return 0;
    case SIOCGIFMAP:
        nfl_log_warn("Ioctl requesting getting l2_iface hardware params (SIOCGIFMAP), return dummy value");
        memset(&my_ifreq->ifr_map, 0, sizeof(struct ifmap));
        return 0;
    case SIOCGIFMETRIC:
        nfl_log_warn("Ioctl requesting getting l2_iface metric (SIOCGIFMETRIC), silent ignore, return 0 as metric, same behaviour as glibc");
        my_ifreq->ifr_metric = 0;
        return 0;
    case SIOCSIFMETRIC:
        nfl_log_warn("Ioctl requesting setting l2_iface metric (SIOCSIFMETRIC), return EOPNOTSUPP, same behaviour as glibc");
        return -EOPNOTSUPP; //Same as glibc behaviour
        IOCTL_CASE(SIOCSIFFLAGS, "requesting setting l2_iface flags (SIOCSIFFLAGS), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFPFLAGS, "requesting setting extended network l2_iface flags (SIOCSIFPFLAGS), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFADDR, "requesting setting l2_iface ipv4/v6 address (SIOCSIFADDR), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCDIFADDR, "requesting deleting l2_iface ipv6 address (SIOCDIFADDR), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCGIFDSTADDR, "requesting action on point to point l2_iface (SIOCGIFDSTADDR), returning operation not supported (EOPNOTSUPP)",
                   -EOPNOTSUPP);
        IOCTL_CASE(SIOCSIFDSTADDR, "requesting action on point to point l2_iface (SIOCGIFDSTADDR), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFHWADDR, "requesting setting l2_iface hardware address (SIOCSIFHWADDR), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFBRDADDR, "requesting setting l2_iface ipv4 broadcast address (SIOCSIFBRDADDR), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFNETMASK, "requesting setting l2_iface netmask (SIOCSIFNETMASK), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFMTU, "requesting setting l2_iface mtu (SIOCSIFMTU), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFHWBROADCAST, "requesting setting hardware broadcast address (SIOCSIFHWBROADCAST), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFMAP, "requesting setting l2_iface hardware params (SIOCSIFMAP), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCADDMULTI, "requesting adding link layer multicast filter address from l2_iface (SIOCADDMULTI), returning no permissions (EPERM)",
                   -EPERM);
        IOCTL_CASE(SIOCDELMULTI, "requesting deleting link layer multicast filter address from l2_iface (SIOCDELMULTI), returning no permissions (EPERM)",
                   -EPERM);
        IOCTL_CASE(SIOCSIFTXQLEN, "requesting setting transmit queue length to l2_iface (SIOCGIFTXQLEN), returning no permissions (EPERM)", -EPERM);
        IOCTL_CASE(SIOCSIFNAME, "requesting changing l2_iface name (SIOCSIFNAME), returning no permissions (EPERM)", -EPERM);
    default:
        return -EINVAL;
    }
}