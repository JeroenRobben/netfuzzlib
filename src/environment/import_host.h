#ifndef NETFUZZLIB_IMPORT_HOST_H
#define NETFUZZLIB_IMPORT_HOST_H
#include "sockets/network_types.h"

#define PROC_NET_IF_INET6 "/proc/net/if_inet6"
#define PROC_NET_ROUTE "/proc/net/route"
#define PROC_NET_IPV6_ROUTE "/proc/net/ipv6_route"
#define SYS_CLASS_NET "/sys/class/net/"
#define SYS_CLASS_NET_MTU "/sys/class/net/%s/mtu"
#define SYS_CLASS_NET_FLAGS "/sys/class/net/%s/flags"
#define SYS_CLASS_NET_INDEX "/sys/class/net/%s/ifindex"
#define SYS_CLASS_NET_HW_ADDRESS "/sys/class/net/%s/address"
#define SYS_CLASS_NET_HW_ADDRESS_LEN "/sys/class/net/%s/addr_len"
#define SYS_CLASS_NET_HW_ADDRESS_BROADCAST "/sys/class/net/%s/broadcast"

/*
 * Add a copy of the systems network l2_interfaces and l3_interfaces to the network environment.
 * This reduces the chance of discrepancies between the modelled network environment
 * and possible calls to the OS which are not modelled (e.g. interaction with NETLINK)
 */
void import_host_network_devices();

#endif // NETFUZZLIB_IMPORT_HOST_H
