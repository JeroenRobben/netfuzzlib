#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>

#include <gtest/gtest.h>

extern "C" {
#include "netfuzzlib/module_api.h"
#include "module.h"
#include "environment/network_env.h"
}

struct my_in6_pktinfo {
    struct in6_addr ipi6_addr; /* src/dst IPv6 address */
    unsigned int ipi6_ifindex; /* send/recv interface index */
};

class TestICMP : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/icmp.conf");
    }
};

TEST_F(TestICMP, test_icmpv6_recvpktinfo) {
    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_LT(0, fd);
    int opt = 1;
    ASSERT_NE(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt)), -1);
    int opt_returned = 0;
    socklen_t opt_returned_len = sizeof(opt_returned);
    ASSERT_NE(getsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt_returned, &opt_returned_len), -1);
    ASSERT_TRUE(opt_returned);

    char interface_name[IF_NAMESIZE + 1];
    char ipv6_address[INET6_ADDRSTRLEN];

    struct msghdr msg;

    char packet_data[1000];

    struct iovec iov;
    iov.iov_base = packet_data;
    iov.iov_len = sizeof(packet_data);

    char controlmsg[CMSG_SPACE(sizeof(struct my_in6_pktinfo))];

    struct sockaddr_in6 from;

    /* Note: use outpacket for input buffer */
    msg.msg_control = &controlmsg;
    msg.msg_controllen = sizeof(controlmsg);
    msg.msg_flags = 0;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov; //&daemon->outpacket;
    msg.msg_iovlen = 1;

    ssize_t ret = recvmsg(fd, &msg, 0);

    ASSERT_EQ(ret, 11);
    ASSERT_FALSE(msg.msg_flags & MSG_CTRUNC);
    struct cmsghdr *cmptr;

    int found_pktinfo = 0;

    for (cmptr = CMSG_FIRSTHDR(&msg); cmptr; cmptr = CMSG_NXTHDR(&msg, cmptr)) {
        if (cmptr->cmsg_level == IPPROTO_IPV6 && cmptr->cmsg_type == IPV6_PKTINFO) {
            found_pktinfo = 1;
            struct my_in6_pktinfo *p = (struct my_in6_pktinfo *)CMSG_DATA(cmptr);
            ASSERT_TRUE(p->ipi6_ifindex); //Interface indexes can't be 0;
            if_indextoname(p->ipi6_ifindex, interface_name);
            ASSERT_STREQ(interface_name, "klee-lo");
            ASSERT_NE(inet_ntop(AF_INET6, &p->ipi6_addr, (char *)&ipv6_address, sizeof(ipv6_address)), nullptr);
            ASSERT_STREQ(ipv6_address, "::1");
        };
    }

    ASSERT_TRUE(found_pktinfo);
}

TEST_F(TestICMP, test_icmpv6_recvpktinfo_cmsg_buffer_to_small) {
    int fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    ASSERT_LT(0, fd);
    int opt = 1;
    ASSERT_NE(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt, sizeof(opt)), -1);
    int opt_returned = 0;
    socklen_t opt_returned_len = sizeof(opt_returned);
    ASSERT_NE(getsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &opt_returned, &opt_returned_len), -1);
    ASSERT_TRUE(opt_returned);

    struct msghdr msg;

    char packet_data[1000];

    struct iovec iov;
    iov.iov_base = packet_data;
    iov.iov_len = sizeof(packet_data);

    char controlmsg[5];

    struct sockaddr_in6 from;

    /* Note: use outpacket for input buffer */
    msg.msg_control = &controlmsg;
    msg.msg_controllen = sizeof(controlmsg);
    msg.msg_flags = 0;
    msg.msg_name = &from;
    msg.msg_namelen = sizeof(from);
    msg.msg_iov = &iov; //&daemon->outpacket;
    msg.msg_iovlen = 1;

    ASSERT_EQ(recvmsg(fd, &msg, 0), 11);
    ASSERT_TRUE(msg.msg_flags & MSG_CTRUNC);
}