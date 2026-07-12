#include "import_host.h"
#include "interfaces.h"
#include "interceptors/native.h"
#include <netfuzzlib/callbacks.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/route.h>

static int parse_int_from_file(const char *path, const char *format_string, int *value) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    const int rc = fscanf(fp, format_string, value);
    fclose(fp);
    if (rc < 1) {
        return -1;
    }
    return 0;
}

static int parse_mac_from_file(const char *path, char *mac) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return -1;
    }
    // NOLINTNEXTLINE(cert-err34-c,bugprone-unchecked-string-to-number-conversion)
    const int rc = fscanf(fp, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx%*c", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    fclose(fp);
    if (rc < 1) {
        return -1;
    }
    return 0;
}

static void import_l3_ifaces_from_local_l2_iface_ipv6(const nfl_l2_iface_t *l2_iface) {
    FILE *fp = fopen(PROC_NET_IF_INET6, "r");
    if (!fp) {
        nfl_die(1, "Error adding ipv6 address(es), could not read /proc/net/if_inet6");
    }

    struct sockaddr_in6 addr;
    char addr_string[INET6_ADDRSTRLEN];
    char device_name_parsed[IF_NAMESIZE + 1];
    char ipv6_hex_string[(16 * 2) + 1];
    char ipv6_hex[16];
    int scope;
    int index;
    int prefix_length;
    int flags;

    // NOLINTNEXTLINE(cert-err34-c,bugprone-unchecked-string-to-number-conversion)
    while ((fscanf(fp, "%32s %x %x %x %x %s", ipv6_hex_string, &index, &prefix_length, &scope, &flags, device_name_parsed)) == 6) {
        if (strcmp(device_name_parsed, l2_iface->name) == 0) {
            for (size_t i = 0; i < sizeof(ipv6_hex); i++) {
                // NOLINTNEXTLINE(cert-err34-c,bugprone-unchecked-string-to-number-conversion)
                sscanf(ipv6_hex_string + (2 * i), "%2hhx", &ipv6_hex[i]);
            }
            memcpy(&addr.sin6_addr, ipv6_hex, sizeof(ipv6_hex));

            if (inet_ntop(AF_INET6, &addr.sin6_addr, addr_string, sizeof(struct sockaddr_in6))) {
                nfl_add_l3_iface_ipv6(l2_iface->index, addr_string, prefix_length, scope);
            }
        }
    }
    fclose(fp);
}

static void import_l3_ifaces_from_local_l2_iface_ipv4(nfl_l2_iface_t *l2_iface) {
    struct ifreq my_ifreq;
    struct sockaddr_in address;
    struct sockaddr_in netmask;
    char addr_string[INET_ADDRSTRLEN];
    char netmask_addr_string[INET_ADDRSTRLEN];

    snprintf(my_ifreq.ifr_name, IFNAMSIZ, "%s", l2_iface->name);
    const int fd = socket_native(AF_INET, SOCK_DGRAM, 0);
    if (!fd) {
        return;
    }
    if (ioctl_native(fd, SIOCGIFADDR, &my_ifreq) != 0) {
        return;
    }
    memcpy(&address, &my_ifreq.ifr_addr, sizeof(struct sockaddr_in));
    if (ioctl_native(fd, SIOCGIFNETMASK, &my_ifreq) != 0) {
        return;
    }
    memcpy(&netmask, &my_ifreq.ifr_addr, sizeof(struct sockaddr_in));

    inet_ntop(AF_INET, &address.sin_addr, addr_string, sizeof(struct sockaddr_in));
    inet_ntop(AF_INET, &netmask.sin_addr, netmask_addr_string, sizeof(struct sockaddr_in));

    nfl_add_l3_iface_ipv4(l2_iface->index, addr_string, netmask_addr_string);
}

/**
 * Add a representation of a local L2 interface to the modelled network environment.
 * Interfaces with an interface name already present are ignored.
 * @param name the name of the local L2 interface (e.g. eth0)
 */
static void import_l2_iface(const char *name) {
    if (get_l2_iface_by_name(name)) {
        nfl_log("Skipping host iface %s: already present in model", name);
        return;
    }

    char sys_mtu_path[sizeof(SYS_CLASS_NET_MTU) + IFNAMSIZ];
    char sys_flags_path[sizeof(SYS_CLASS_NET_FLAGS) + IFNAMSIZ];
    char sys_index_path[sizeof(SYS_CLASS_NET_INDEX) + IFNAMSIZ];
    char sys_hw_addr_len_path[sizeof(SYS_CLASS_NET_HW_ADDRESS_LEN) + IFNAMSIZ];
    char sys_hw_addr_path[sizeof(SYS_CLASS_NET_HW_ADDRESS) + IFNAMSIZ];
    char sys_hw_addr_broadcast_path[sizeof(SYS_CLASS_NET_HW_ADDRESS_BROADCAST) + IFNAMSIZ];

    snprintf(sys_mtu_path, sizeof(SYS_CLASS_NET_MTU) + IFNAMSIZ, SYS_CLASS_NET_MTU, name);
    snprintf(sys_flags_path, sizeof(SYS_CLASS_NET_FLAGS) + IFNAMSIZ, SYS_CLASS_NET_FLAGS, name);
    snprintf(sys_index_path, sizeof(SYS_CLASS_NET_INDEX) + IFNAMSIZ, SYS_CLASS_NET_INDEX, name);
    snprintf(sys_hw_addr_path, sizeof(SYS_CLASS_NET_HW_ADDRESS) + IFNAMSIZ, SYS_CLASS_NET_HW_ADDRESS, name);
    snprintf(sys_hw_addr_len_path, sizeof(SYS_CLASS_NET_HW_ADDRESS_LEN) + IFNAMSIZ, SYS_CLASS_NET_HW_ADDRESS_LEN, name);
    snprintf(sys_hw_addr_broadcast_path, sizeof(SYS_CLASS_NET_HW_ADDRESS_BROADCAST) + IFNAMSIZ, SYS_CLASS_NET_HW_ADDRESS_BROADCAST, name);

    int mtu;
    int flags;
    int addr_len;
    char hw_addr[ETHER_ADDR_LEN] = { 0 };
    char hw_broadcast_addr[ETHER_ADDR_LEN] = { 0 };

    if (parse_int_from_file(sys_mtu_path, "%d", &mtu) == -1) {
        nfl_die(1, "Could not read MTU from SYS fs");
    }
    if (parse_int_from_file(sys_flags_path, "0x%x", &flags) == -1) {
        nfl_die(1, "Could not read flags from SYS fs");
    }
    if (parse_int_from_file(sys_hw_addr_len_path, "%d", &addr_len) == -1) {
        nfl_die(1, "Could not read hw addr len from SYS fs");
    }
    // Non-Ethernet interfaces (TUN, sit, ...) have addr_len != 6 and their
    // address/broadcast sysfs files are empty. Import them with a zeroed MAC
    // so callers still see the interface in the model.
    if (addr_len == ETHER_ADDR_LEN) {
        if (parse_mac_from_file(sys_hw_addr_path, hw_addr) == -1) {
            nfl_die(1, "Could not read hw addr from SYS fs");
        }
        if (parse_mac_from_file(sys_hw_addr_broadcast_path, hw_broadcast_addr) == -1) {
            nfl_die(1, "Could not read hw broadcast addr from SYS fs");
        }
    } else {
        nfl_log("Importing non-Ethernet host iface %s (addr_len=%d) with zeroed hw address", name, addr_len);
    }

    // Add the new l2_iface to the environment
    unsigned int index;
    if (nfl_add_l2_iface(name, (short)flags, mtu, hw_addr, hw_broadcast_addr, &index) != 0) {
        nfl_die(1, "Could not add local l2_iface");
    }

    nfl_l2_iface_t *l2_iface = get_l2_iface_by_index(index);
    // Add the l3_interfaces associated with this l2_iface
    import_l3_ifaces_from_local_l2_iface_ipv4(l2_iface);
    import_l3_ifaces_from_local_l2_iface_ipv6(l2_iface);
}

static void import_default_gateway_ipv4() {
    FILE *file = fopen(PROC_NET_ROUTE, "r");
    if (!file) {
        nfl_die(1, "Could not read %s", PROC_NET_ROUTE);
    }
    char *line = NULL;
    size_t len = 0;
    bool gateway_found = false;
    if (getline(&line, &len, file) < 0) {
        goto cleanup;
    }
    while (getline(&line, &len, file) > 0 && !gateway_found) {
        char *line_cp = line;

        const char *device_str = strsep(&line_cp, "\t");
        const char *destination_str = strsep(&line_cp, "\t");
        const char *gateway_str = strsep(&line_cp, "\t");
        const char *flags_str = strsep(&line_cp, "\t");
        //        char *refcnt = strsep(&line_cp, "\t");
        //        char *use = strsep(&line_cp, "\t");
        //        char *metric = strsep(&line_cp, "\t");
        //        char *mask = strsep(&line_cp, "\t");
        //        char *mtu = strsep(&line_cp, "\t");
        //        char *window = strsep(&line_cp, "\t");
        //        char *irtt = strsep(&line_cp, "\t");
        const long flags = strtol(flags_str, NULL, 10);
        if ((flags & RTF_GATEWAY) && strcmp("00000000", destination_str) == 0) {
            struct in_addr gateway_addr;
            gateway_addr.s_addr = strtol(gateway_str, NULL, 16);
            const char *gateway_addr_parsed = inet_ntoa(gateway_addr);
            nfl_set_ipv4_default_gateway(gateway_addr_parsed, if_nametoindex(device_str));
            gateway_found = true;
        }
    }
    if (!gateway_found) {
        nfl_log("Could not import IPv4 default gateway from host device, are you connected to the internet?");
    }
cleanup:
    free(line);
    fclose(file);
}

static void import_default_gateway_ipv6() {
    FILE *file = fopen(PROC_NET_IPV6_ROUTE, "r");
    if (!file) {
        nfl_die(1, "Could not read %s", PROC_NET_IPV6_ROUTE);
    }
    char *line = NULL;
    size_t len = 0;
    bool gateway_found = false;
    if (getline(&line, &len, file) < 0) {
        goto cleanup;
    }
    while (getline(&line, &len, file) > 0 && !gateway_found) {
        char *line_cp = line;

        const char *destination_str = strsep(&line_cp, " ");
        const char *destination_prefix_str = strsep(&line_cp, " ");
        (void)strsep(&line_cp, " "); // source
        (void)strsep(&line_cp, " "); // source prefix
        const char *next_hop_str = strsep(&line_cp, " ");
        (void)strsep(&line_cp, " "); // metric
        (void)strsep(&line_cp, " "); // refcnt
        (void)strsep(&line_cp, " "); // use
        const char *flags_str = strsep(&line_cp, " ");
        char *device_str = strsep(&line_cp, "\n");
        while (*device_str == ' ') {
            device_str++; // Remove leading spaces
        }
        if (device_str[strlen(device_str)] == '\n') {
            device_str[strlen(device_str)] = '\0'; // Remove \n
        }

        const long flags = strtol(flags_str, NULL, 10);

        if ((flags & RTF_GATEWAY) && strcmp("00000000000000000000000000000000", destination_str) == 0 && strcmp("00", destination_prefix_str) == 0) {
            struct in6_addr next_hop;
            char *next_hop_bytes = (char *)&next_hop;
            // NOLINTNEXTLINE(cert-err34-c,bugprone-unchecked-string-to-number-conversion)
            const int ret = sscanf(next_hop_str, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx", &next_hop_bytes[0],
                                   &next_hop_bytes[1], &next_hop_bytes[2], &next_hop_bytes[3], &next_hop_bytes[4], &next_hop_bytes[5], &next_hop_bytes[6],
                                   &next_hop_bytes[7], &next_hop_bytes[8], &next_hop_bytes[9], &next_hop_bytes[10], &next_hop_bytes[11], &next_hop_bytes[12],
                                   &next_hop_bytes[13], &next_hop_bytes[14], &next_hop_bytes[15]);
            if (ret != 16) {
                nfl_log("Error parsing %s", PROC_NET_IPV6_ROUTE);
                break;
            }
            char next_hop_str_parsed[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, &next_hop, next_hop_str_parsed, sizeof(next_hop_str_parsed));
            nfl_set_ipv6_default_gateway(next_hop_str_parsed, if_nametoindex(device_str));
            gateway_found = true;
        }
    }

    if (!gateway_found) {
        nfl_log("Could not import IPv6 default gateway from host device, are you connected to the internet?");
    }

cleanup:
    free(line);
    fclose(file);
}

void nfl_import_host_network_devices() {
    // Read all entries in /sys/class/net.
    // These represent real or virtual network l2_interfaces of the local system, see man 5 sysfs.

    struct dirent *dir_entry;
    DIR *dir_handle = opendir(SYS_CLASS_NET);
    if (!dir_handle) {
        nfl_die(1, "Could not read /sys/class/net");
    }
    while ((dir_entry = readdir(dir_handle))) {
        if (strcmp(dir_entry->d_name, ".") != 0 && strcmp(dir_entry->d_name, "..") != 0) {
            import_l2_iface(dir_entry->d_name);
        }
    }
    closedir(dir_handle);
    import_default_gateway_ipv4();
    import_default_gateway_ipv6();
}
