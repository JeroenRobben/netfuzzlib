#include <gtest/gtest.h>

extern "C" {
#include <arpa/inet.h>
#include <assert.h>
#include <errno.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../../../src/environment/network_env.h"
#include "module.h"
}

#define KLEE_LO "klee-lo"
#define KLEE_LO_IPV4 "127.0.0.1"
#define KLEE_LO_IPV4_NETMASK "255.0.0.0"
#define KLEE_LO_IPV6 "::1"

#define KLEE_ETH0 "klee-eth0"
#define KLEE_ETH0_IPV4 "192.168.1.2"
#define KLEE_ETH0_IPV4_NETMASK "255.255.255.0"
#define KLEE_ETH0_IPV4_BROADCAST "192.168.1.255"
#define KLEE_ETH0_MTU 1500

#define KLEE_ETH0_IPV6_PREFIX 64
#define KLEE_ETH0_IPV6_LINK "fe80::5859:71af:177e:db7a"
#define KLEE_ETH0_IPV6_GLOBAL "2a02::ab43:c679"

class TestEnvironmentIoctl : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/ioctl1.conf");
    }
};

TEST_F(TestEnvironmentIoctl, test_indextoname) {
    char test_device_name[IF_NAMESIZE] = "";

    unsigned int index_lo = if_nametoindex(KLEE_LO);
    ASSERT_NE(index_lo, 0);
    ASSERT_TRUE(if_indextoname(index_lo, test_device_name));
    ASSERT_STREQ(test_device_name, KLEE_LO);

    unsigned int index_eth0 = if_nametoindex(KLEE_ETH0);
    ASSERT_NE(index_eth0, 0);
    ASSERT_TRUE(if_indextoname(index_eth0, test_device_name));
    ASSERT_STREQ(test_device_name, KLEE_ETH0);
}

TEST_F(TestEnvironmentIoctl, test_ioctl_lo) {
    struct ifreq ifr;
    strcpy(ifr.ifr_name, KLEE_LO);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_LT(0, fd);
    ASSERT_EQ(ioctl(fd, SIOCGIFFLAGS, &ifr), 0);
    ASSERT_EQ(ifr.ifr_flags, 73);
    ASSERT_EQ(ioctl(fd, SIOCSIFFLAGS, &ifr), -EPERM);

    ASSERT_EQ(ioctl(fd, SIOCGIFMTU, &ifr), 0);
    ASSERT_EQ(ifr.ifr_mtu, 65536);

    ASSERT_EQ(ioctl(fd, SIOCGIFADDR, &ifr), 0);
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    ASSERT_EQ(addr->sin_family, AF_INET);
    char *addr_str = inet_ntoa(addr->sin_addr);
    ASSERT_STREQ(addr_str, KLEE_LO_IPV4);

    ASSERT_EQ(ioctl(fd, SIOCSIFADDR, &ifr), -EPERM);
    ASSERT_EQ(ioctl(fd, SIOCDIFADDR, &ifr), -EPERM);
    ASSERT_EQ(ioctl(fd, SIOCGIFDSTADDR, &ifr), -EOPNOTSUPP);
    ASSERT_EQ(ioctl(fd, SIOCSIFDSTADDR, &ifr), -EPERM);

    ASSERT_EQ(ioctl(fd, SIOCGIFNETMASK, &ifr), 0);
    ASSERT_EQ(addr->sin_family, AF_INET);
    addr_str = inet_ntoa(addr->sin_addr);
    ASSERT_STREQ(addr_str, KLEE_LO_IPV4_NETMASK);
    close(fd);
}

TEST_F(TestEnvironmentIoctl, test_ioctl_eth0) {
    struct ifreq ifr;
    strcpy(ifr.ifr_name, KLEE_ETH0);
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_LT(0, fd);
    ASSERT_EQ(ioctl(fd, SIOCGIFFLAGS, &ifr), 0);
    ASSERT_EQ(ifr.ifr_flags, 4163);
    ASSERT_EQ(ioctl(fd, SIOCSIFFLAGS, &ifr), -EPERM);

    ASSERT_EQ(ioctl(fd, SIOCGIFADDR, &ifr), 0);
    struct sockaddr_in *addr = (struct sockaddr_in *)&ifr.ifr_addr;
    ASSERT_EQ(addr->sin_family, AF_INET);
    char *addr_str = inet_ntoa(addr->sin_addr);
    ASSERT_EQ(strcmp(addr_str, KLEE_ETH0_IPV4), 0);

    ASSERT_EQ(ioctl(fd, SIOCSIFADDR, &ifr), -EPERM);
    ASSERT_EQ(ioctl(fd, SIOCDIFADDR, &ifr), -EPERM);
    ASSERT_EQ(ioctl(fd, SIOCGIFDSTADDR, &ifr), -EOPNOTSUPP);
    ASSERT_EQ(ioctl(fd, SIOCSIFDSTADDR, &ifr), -EPERM);

    ASSERT_EQ(ioctl(fd, SIOCGIFNETMASK, &ifr), 0);
    ASSERT_EQ(addr->sin_family, AF_INET);
    addr_str = inet_ntoa(addr->sin_addr);
    ASSERT_EQ(strcmp(addr_str, KLEE_ETH0_IPV4_NETMASK), 0);

    ASSERT_EQ(ioctl(fd, SIOCGIFBRDADDR, &ifr), 0);
    ASSERT_EQ(addr->sin_family, AF_INET);
    addr_str = inet_ntoa(addr->sin_addr);
    ASSERT_EQ(strcmp(addr_str, KLEE_ETH0_IPV4_BROADCAST), 0);

    ASSERT_EQ(ioctl(fd, SIOCGIFMTU, &ifr), 0);
    ASSERT_EQ(ifr.ifr_mtu, KLEE_ETH0_MTU);
    close(fd);
}

TEST_F(TestEnvironmentIoctl, test_ioctl_SIOCGIFCONF) {
    struct ifconf ifc;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifc.ifc_len = 0;
    ifc.ifc_req = NULL;
    ASSERT_EQ(ioctl(fd, SIOCGIFCONF, &ifc), 0);
    ASSERT_TRUE(ifc.ifc_len);
    ASSERT_FALSE(ifc.ifc_req);
    int amount_addrs = ifc.ifc_len / ((int)sizeof(struct ifreq));
    ASSERT_EQ(amount_addrs, 3);
    ifc.ifc_req = (struct ifreq *)calloc(ifc.ifc_len, 1);
    ASSERT_TRUE(ifc.ifc_req);
    ASSERT_EQ(ioctl(fd, SIOCGIFCONF, &ifc), 0);

    struct ifreq *ifr;
    int i;
    bool lo_seen = false;
    bool eth0_seen = false;
    for (i = 0; i < amount_addrs; i++) {
        ifr = &ifc.ifc_req[i];
        ASSERT_TRUE(ifr->ifr_addr.sa_family == AF_INET);
        struct sockaddr_in *addr = (struct sockaddr_in *)&ifr->ifr_addr;
        char *addr_str = inet_ntoa(addr->sin_addr);
        if (strcmp(addr_str, KLEE_LO_IPV4) == 0)
            lo_seen = true;
        else if (strcmp(addr_str, KLEE_ETH0_IPV4) == 0)
            eth0_seen = true;
    }
    ASSERT_TRUE(lo_seen);
    ASSERT_TRUE(eth0_seen);

    close(fd);
}

TEST_F(TestEnvironmentIoctl, test_getifaddrs) {
    struct ifaddrs *ifaddr;
    int family, s;
    char host[INET6_ADDRSTRLEN];

    assert(getifaddrs(&ifaddr) == 0);

    bool lo_ipv4_seen = false;
    bool lo_ipv6_seen = false;
    bool klee_lo_ipv4_seen = false;
    bool klee_lo_ipv6_seen = false;
    bool eth0_ipv4_seen = false;
    bool eth0_ipv6_link_seen = false;
    bool eth0_ipv6_global_seen = false;

    int amount_interfaces_seen = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        ASSERT_TRUE(ifa->ifa_addr);
        amount_interfaces_seen++;
        family = ifa->ifa_addr->sa_family;
        memset(host, 0, sizeof(host));
        const char *ret_ptr = family == AF_INET ? inet_ntop(family, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, host, INET6_ADDRSTRLEN) :
                                                  inet_ntop(family, &((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr, host, INET6_ADDRSTRLEN);
        ASSERT_EQ(ret_ptr, host);

        if (strcmp(ifa->ifa_name, KLEE_LO) == 0) {
            if (family == AF_INET) {
                ASSERT_STREQ(host, KLEE_LO_IPV4);
                klee_lo_ipv4_seen = true;
            } else if (family == AF_INET6) {
                ASSERT_STREQ(host, KLEE_LO_IPV6);
                klee_lo_ipv6_seen = true;
            } else
                FAIL();
        } else if (strcmp(ifa->ifa_name, KLEE_ETH0) == 0) {
            if (family == AF_INET) {
                ASSERT_STREQ(host, KLEE_ETH0_IPV4);
                eth0_ipv4_seen = true;
            } else if (family == AF_INET6) {
                if (strcmp(host, KLEE_ETH0_IPV6_LINK) == 0) {
                    eth0_ipv6_link_seen = true;
                } else if (strcmp(host, KLEE_ETH0_IPV6_GLOBAL) == 0) {
                    eth0_ipv6_global_seen = true;
                } else {
                } //FAIL();}

            } else
                FAIL();
        } else if (strcmp(ifa->ifa_name, "lo") == 0) {
            if (family == AF_INET) {
                ASSERT_STREQ(host, KLEE_LO_IPV4);
                lo_ipv4_seen = true;
            } else if (family == AF_INET6) {
                ASSERT_STREQ(host, KLEE_LO_IPV6);
                lo_ipv6_seen = true;
            } else
                FAIL();
        } else {
            printf("Error device name %s\n", ifa->ifa_name);
            FAIL();
        }
    }

    ASSERT_TRUE(lo_ipv4_seen);
    ASSERT_TRUE(lo_ipv6_seen);
    ASSERT_TRUE(klee_lo_ipv4_seen);
    ASSERT_TRUE(klee_lo_ipv6_seen);
    ASSERT_TRUE(eth0_ipv4_seen);
    ASSERT_TRUE(eth0_ipv6_link_seen);
    ASSERT_TRUE(eth0_ipv6_global_seen);
    ASSERT_EQ(amount_interfaces_seen, 7);

    freeifaddrs(ifaddr);
}
