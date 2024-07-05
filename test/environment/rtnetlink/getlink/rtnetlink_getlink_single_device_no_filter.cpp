// RUN: %clang %s -emit-llvm -O0 -c -g -o %t1.bc
// RUN: rm -rf %t.klee-out-tmp
// RUN: %klee --output-dir=%t.klee-out-tmp --libc=uclibc --posix-runtime --exit-on-error %t1.bc --sym-network-no-local --sym-network-config-file %S/../rtnetlink_lo_ipv4.conf > %t.log

#include <arpa/inet.h>
#include <assert.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define BUFSIZE 8192

#include <gtest/gtest.h>
#include "rtnetlink_getlink_test_helper.h"

extern "C" {
#include "../../../../include/netfuzzlib/module_api.h"
#include "module.h"
#include "../../../../src/environment/network_env.h"
}

struct nl_req_s {
    struct nlmsghdr hdr;
    struct ifinfomsg gen;
};

class TestRTNetlinkGetLinkSingleDeviceNoFilter : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/empty.conf");
    }
};

TEST_F(TestRTNetlinkGetLinkSingleDeviceNoFilter, test_getlink_lo) {
    struct sockaddr_nl kernel;
    int s, end = 0;
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
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT;
    req.hdr.nlmsg_seq = 1;
    req.hdr.nlmsg_pid = 1000;

    req.gen.ifi_family = AF_INET6; //Should be ignored
    req.gen.ifi_index = 10; //Should be ignored

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
    memset(buf, 0, BUFSIZE);
    msg.msg_iov->iov_base = buf;
    msg.msg_iov->iov_len = BUFSIZE;

    len = recvmsg(s, &msg, MSG_DONTWAIT);
    ASSERT_LT(0, len);

    struct nlmsghdr *msg_ptr = (struct nlmsghdr *)buf;
    ASSERT_TRUE(NLMSG_OK(msg_ptr, len));
    ASSERT_TRUE(msg_ptr->nlmsg_flags & NLM_F_MULTI);
    ASSERT_EQ(msg_ptr->nlmsg_type, RTM_NEWLINK);

    char mac_zero[ETHER_ADDR_LEN];
    memset(&mac_zero, 0, sizeof(mac_zero));

    test_link(msg_ptr, "lo", mac_zero, mac_zero, 65536, 73);

    msg_ptr = NLMSG_NEXT(msg_ptr, len);
    ASSERT_FALSE(NLMSG_OK(msg_ptr, len));
    close(s);
}
