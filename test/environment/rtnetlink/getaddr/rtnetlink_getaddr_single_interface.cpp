#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
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

class TestRTNetlinkSingleInterface : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/empty.conf");
    }
};

static void check_addr(struct nlmsghdr *hdr) {
    struct ifaddrmsg *addr;
    struct rtattr *attr;
    unsigned long len;

    addr = (struct ifaddrmsg *)NLMSG_DATA(hdr);
    len = hdr->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr)) - NLMSG_ALIGN(sizeof(struct ifaddrmsg));

    assert(addr->ifa_family == AF_INET);
    assert(addr->ifa_prefixlen == 8);
    assert(addr->ifa_scope == RT_SCOPE_HOST);
    assert(addr->ifa_index == 1);
    assert(addr->ifa_flags == IFA_F_PERMANENT);

    bool ifa_label_seen = false, ifa_local_seen = false, ifa_address_seen = false, ifa_broadcast_seen = false, ifa_flags_seen = false,
         ifa_cacheinfo_seen = false;

    int attr_count = 0;
    for (attr = IFA_RTA(addr); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        attr_count++;
        switch (attr->rta_type) {
        case IFA_LABEL:
            ifa_label_seen = true;
            ASSERT_STREQ((char *)RTA_DATA(attr), "lo");
            break;
        case IFA_LOCAL: {
            ifa_local_seen = true;
            assert(*(in_addr_t *)RTA_DATA(attr) == inet_addr("127.0.0.1"));
            break;
        }
        case IFA_ADDRESS: {
            ifa_address_seen = true;
            assert(*(in_addr_t *)RTA_DATA(attr) == inet_addr("127.0.0.1"));
            break;
        }
        case IFA_BROADCAST: {
            ifa_broadcast_seen = true;
            assert(*(in_addr_t *)RTA_DATA(attr) == inet_addr("127.255.255.255"));
            break;
        }
        case IFA_FLAGS: {
            ifa_flags_seen = true;
            assert(*(int *)RTA_DATA(attr) == IFA_F_PERMANENT);
            break;
        }
        case IFA_CACHEINFO: {
            ifa_cacheinfo_seen = true;
            struct ifa_cacheinfo *cacheinfo = (struct ifa_cacheinfo *)RTA_DATA(attr);
            assert(cacheinfo->tstamp == 20000);
            assert(cacheinfo->cstamp == 10000);
            assert(cacheinfo->ifa_valid == 3000);
            assert(cacheinfo->ifa_prefered == 3000);
            break;
        }
        default:
            assert(0 && "Unknown flags!");
            break;
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

TEST_F(TestRTNetlinkSingleInterface, test_getaddr_single_interface) {
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
    memset(buf, 0, BUFSIZE);
    msg.msg_iov->iov_base = buf;
    msg.msg_iov->iov_len = BUFSIZE;
    len = recvmsg(s, &msg, MSG_DONTWAIT);
    ASSERT_GT(len, 0);

    struct nlmsghdr *msg_ptr = (struct nlmsghdr *)buf;
    ASSERT_TRUE(NLMSG_OK(msg_ptr, len));
    ASSERT_TRUE(msg_ptr->nlmsg_flags & NLM_F_MULTI);
    ASSERT_EQ(msg_ptr->nlmsg_type, RTM_NEWADDR);
    check_addr(msg_ptr);
    msg_ptr = NLMSG_NEXT(msg_ptr, len);
    ASSERT_FALSE(NLMSG_OK(msg_ptr, len));

    close(s);
}
