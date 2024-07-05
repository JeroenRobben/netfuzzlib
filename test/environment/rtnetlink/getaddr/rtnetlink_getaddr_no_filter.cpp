// RUN: %clang %s -emit-llvm -O0 -c -g -o %t1.bc
// RUN: rm -rf %t.klee-out-tmp
// RUN: %klee --output-dir=%t.klee-out-tmp --libc=uclibc --posix-runtime --exit-on-error %t1.bc --sym-network-no-local --sym-network-config-file %S/../rtnetlink-multiple-interfaces.conf > %t.log

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>

extern "C" {
#include "../../../../include/netfuzzlib/module_api.h"
#include "module.h"
#include "../../../../src/environment/network_env.h"
}
#define BUFSIZE 8192

struct nl_req_s {
    struct nlmsghdr hdr;
    struct rtgenmsg gen;
};

bool ipv4_lan_seen = false, ipv4_global_seen = false, ipv6_global_seen = false, ipv6_lan_seen = false;

class TestRTNetlinkGetaddrNoFilter : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/rtnetlink-multiple-interfaces.conf");
    }
};

void test_addr_ipv6(struct nlmsghdr *msg, struct in6_addr *address, int flags) {
    struct ifaddrmsg *addr;
    struct rtattr *attr;
    unsigned long len;

    addr = (struct ifaddrmsg *)NLMSG_DATA(msg);
    len = msg->nlmsg_len - NLMSG_ALIGN(NLMSG_ALIGN(sizeof(struct nlmsghdr)) + sizeof(struct ifaddrmsg));

    bool ifa_address_seen = false, ifa_flags_seen = false, ifa_cacheinfo_seen = false;

    int attr_count = 0;
    for (attr = IFA_RTA(addr); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        attr_count++;
        switch (attr->rta_type) {
        case IFA_ADDRESS: {
            ifa_address_seen = true;
            ASSERT_TRUE(memcmp(RTA_DATA(attr), address, sizeof(struct in6_addr)) == 0);
            break;
        }
        case IFA_FLAGS: {
            ifa_flags_seen = true;
            ASSERT_EQ(*(int *)RTA_DATA(attr), flags);
            break;
        }
        case IFA_CACHEINFO: {
            ifa_cacheinfo_seen = true;
            struct ifa_cacheinfo *cacheinfo = (struct ifa_cacheinfo *)RTA_DATA(attr);
            ASSERT_EQ(cacheinfo->tstamp, 20000);
            ASSERT_EQ(cacheinfo->cstamp, 10000);
            ASSERT_EQ(cacheinfo->ifa_valid, 3000);
            ASSERT_EQ(cacheinfo->ifa_prefered, 3000);
            break;
        }
        default: {
            FAIL();
            //"Unknown flags!"
        }
        }
    }
    ASSERT_TRUE(ifa_address_seen);
    ASSERT_TRUE(ifa_flags_seen);
    ASSERT_TRUE(ifa_cacheinfo_seen);
    ASSERT_EQ(attr_count, 3);
}

void test_addr_ipv4(struct nlmsghdr *msg, char *label, in_addr_t local, in_addr_t address, in_addr_t broadcast, int flags) {
    struct ifaddrmsg *addr;
    struct rtattr *attr;
    unsigned long len;

    addr = (struct ifaddrmsg *)NLMSG_DATA(msg);
    len = msg->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr)) - NLMSG_ALIGN(sizeof(struct ifaddrmsg));

    bool ifa_label_seen = false, ifa_local_seen = false, ifa_address_seen = false, ifa_broadcast_seen = false, ifa_flags_seen = false,
         ifa_cacheinfo_seen = false;

    int attr_count = 0;
    for (attr = IFA_RTA(addr); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        attr_count++;
        switch (attr->rta_type) {
        case IFA_LABEL:
            ifa_label_seen = true;
            ASSERT_STREQ((char *)RTA_DATA(attr), label);
            break;
        case IFA_LOCAL: {
            ifa_local_seen = true;
            ASSERT_EQ(*(in_addr_t *)RTA_DATA(attr), local);
            break;
        }
        case IFA_ADDRESS: {
            ifa_address_seen = true;
            ASSERT_EQ(*(in_addr_t *)RTA_DATA(attr), address);
            break;
        }
        case IFA_BROADCAST: {
            ifa_broadcast_seen = true;
            ASSERT_EQ(*(in_addr_t *)RTA_DATA(attr), broadcast);
            break;
        }
        case IFA_FLAGS: {
            ifa_flags_seen = true;
            ASSERT_EQ(*(int *)RTA_DATA(attr), flags);
            break;
        }
        case IFA_CACHEINFO: {
            ifa_cacheinfo_seen = true;
            struct ifa_cacheinfo *cacheinfo = (struct ifa_cacheinfo *)RTA_DATA(attr);
            ASSERT_EQ(cacheinfo->tstamp, 20000);
            ASSERT_EQ(cacheinfo->cstamp, 10000);
            ASSERT_EQ(cacheinfo->ifa_valid, 3000);
            ASSERT_EQ(cacheinfo->ifa_prefered, 3000);
            break;
        }
        default:
            FAIL(); //"Unknown flags!"
        }
    }
    ASSERT_TRUE(ifa_label_seen);
    ASSERT_TRUE(ifa_local_seen);
    ASSERT_TRUE(ifa_address_seen);
    ASSERT_TRUE(ifa_broadcast_seen);
    ASSERT_TRUE(ifa_flags_seen);
    ASSERT_TRUE(ifa_cacheinfo_seen);
    ASSERT_EQ(attr_count, 6);
}

void test_device_3_eth1(struct nlmsghdr *msg) {
    struct ifaddrmsg *addr = (struct ifaddrmsg *)NLMSG_DATA(msg);
    ASSERT_EQ(addr->ifa_flags, IFA_F_PERMANENT);

    if (addr->ifa_family == AF_INET) {
        ASSERT_EQ(addr->ifa_scope, RT_SCOPE_UNIVERSE);
        if (addr->ifa_prefixlen == 8) {
            ipv4_lan_seen = true;
            test_addr_ipv4(msg, (char *)"device-3-eth1", inet_addr("10.0.0.5"), inet_addr("10.0.0.5"), inet_addr("10.255.255.255"), IFA_F_PERMANENT);
        } else if (addr->ifa_prefixlen == 32) {
            ipv4_global_seen = true;
            test_addr_ipv4(msg, (char *)"device-3-eth1", inet_addr("91.34.10.2"), inet_addr("91.34.10.2"), inet_addr("91.34.10.2"), IFA_F_PERMANENT);
        } else
            assert(0);
    } else if (addr->ifa_family == AF_INET6) {
        if (addr->ifa_prefixlen == 32) {
            ipv6_lan_seen = true;
            ASSERT_EQ(addr->ifa_scope, RT_SCOPE_LINK);
            struct in6_addr ipv6_addr;
            inet_pton(AF_INET6, "fe80::5859:71af:177e:db7a", &ipv6_addr);
            test_addr_ipv6(msg, &ipv6_addr, IFA_F_PERMANENT);
        } else if (addr->ifa_prefixlen == 64) {
            ipv6_global_seen = true;
            ASSERT_EQ(addr->ifa_scope, RT_SCOPE_UNIVERSE);
            struct in6_addr ipv6_addr;
            inet_pton(AF_INET6, "2a02::3183:a900:5b63:0019:ab00:c679", &ipv6_addr);
            test_addr_ipv6(msg, &ipv6_addr, IFA_F_PERMANENT);
        } else
            FAIL();
    } else
        FAIL();
}

static void check_addr(struct nlmsghdr *msg) {
    struct ifaddrmsg *addr = (struct ifaddrmsg *)NLMSG_DATA(msg);
    char ifname[IFNAMSIZ];
    ASSERT_EQ(if_indextoname(addr->ifa_index, (char *)&ifname), (void *)&ifname); //if_indextoname should point to second argument on success.
    if (strncmp(ifname, "device-3-eth1", IFNAMSIZ) == 0) {
        test_device_3_eth1(msg);
    }
}

TEST_F(TestRTNetlinkGetaddrNoFilter, test_getaddr) {
    struct sockaddr_nl kernel;
    int s, done = 0;
    ssize_t ret, len;
    struct msghdr msg;
    struct nl_req_s req;
    struct iovec io;
    memset(&kernel, 0, sizeof(kernel));
    kernel.nl_family = AF_NETLINK;
    kernel.nl_groups = 0;

    //create a Netlink socket
    s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    ASSERT_LT(0, s);

    //build netlink message
    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.hdr.nlmsg_pid = 1000;
    req.gen.rtgen_family = 0;

    memset(&io, 0, sizeof(io));
    io.iov_base = &req;
    io.iov_len = req.hdr.nlmsg_len;

    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &io;
    msg.msg_iovlen = 1;
    msg.msg_name = &kernel;
    msg.msg_namelen = sizeof(kernel);

    //send the message
    ret = sendmsg(s, &msg, 0);
    ASSERT_EQ(ret, io.iov_len);

    struct sockaddr_nl peername;
    socklen_t peername_len = sizeof(struct sockaddr_nl);

    ret = getpeername(s, (struct sockaddr *)&peername, &peername_len);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(peername.nl_family, AF_NETLINK);
    ASSERT_EQ(peername.nl_groups, 0);
    ASSERT_EQ(peername.nl_pid, 0);
    char buf[BUFSIZE];

    int msg_count = 0;
    while (!done) {
        memset(buf, 0, BUFSIZE);
        msg.msg_iov->iov_base = buf;
        msg.msg_iov->iov_len = BUFSIZE;
        len = recvmsg(s, &msg, MSG_DONTWAIT);
        ASSERT_LT(0, len);

        for (struct nlmsghdr *msg_ptr = (struct nlmsghdr *)buf; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
            msg_count++;
            ASSERT_TRUE(msg_ptr->nlmsg_flags & NLM_F_MULTI);
            switch (msg_ptr->nlmsg_type) {
            case NLMSG_DONE:
                done++;
                break;
            case RTM_NEWADDR:
                check_addr(msg_ptr);
                break;
            default:
                FAIL(); // "Received unknown message type"
            }
        }
        ASSERT_EQ(len, 0);
    }
    ASSERT_TRUE(ipv4_lan_seen);
    ASSERT_TRUE(ipv6_lan_seen);
    ASSERT_TRUE(ipv6_global_seen);
    ASSERT_TRUE(ipv4_global_seen);

    ASSERT_EQ(msg_count, 10); //9 interfaces + NLMSG_DONE
    close(s);
}