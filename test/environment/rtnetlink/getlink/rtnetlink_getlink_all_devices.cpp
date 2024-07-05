
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <stdbool.h>
#include <cstdlib>
#include <cstring>
#include <sys/socket.h>
#include <unistd.h>

#include <gtest/gtest.h>
#include "rtnetlink_getlink_test_helper.h"

extern "C" {
#include "../../../../include/netfuzzlib/module_api.h"
#include "module.h"
#include "../../../../src/environment/network_env.h"
}

#define BUFSIZE 8192

struct nl_req_s {
    struct nlmsghdr hdr;
    struct ifinfomsg gen;
};

class TestRTNetlinkGetLinkAllDevices : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/rtnetlink-multiple-interfaces.conf");
    }
};

TEST_F(TestRTNetlinkGetLinkAllDevices, test_getlink_all) {
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
    ASSERT_GT(s, 0);

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

    int msg_count = 0;
    bool done = false;
    bool device_1_seen = false, device_2_seen = false, device_3_seen = false, device_lo_seen = false;

    while (!done) {
        memset(buf, 0, BUFSIZE);
        msg.msg_iov->iov_base = buf;
        msg.msg_iov->iov_len = BUFSIZE;
        len = recvmsg(s, &msg, MSG_DONTWAIT);
        ASSERT_GT(len, 0);
        const unsigned char broadcast_mac[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

        for (struct nlmsghdr *msg_ptr = (struct nlmsghdr *)buf; NLMSG_OK(msg_ptr, len); msg_ptr = NLMSG_NEXT(msg_ptr, len)) {
            msg_count++;
            ASSERT_TRUE(msg_ptr->nlmsg_flags & NLM_F_MULTI);
            switch (msg_ptr->nlmsg_type) {
            case NLMSG_DONE: {
                done = true;
                break;
            }
            case RTM_NEWLINK: {
                struct ifinfomsg *ifinfo = (struct ifinfomsg *)NLMSG_DATA(msg_ptr);
                if (ifinfo->ifi_index == 1) {
                    device_lo_seen = true;
                    const unsigned char lo_mac[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    test_link(msg_ptr, "lo", reinterpret_cast<const char *>(lo_mac), reinterpret_cast<const char *>(lo_mac), 65536, 73);
                } else if (ifinfo->ifi_index == 2) {
                    device_1_seen = true;
                    const unsigned char device_1_mac[] = { 0x60, 0x00, 0x00, 0x00, 0x00, 0x00 };
                    test_link(msg_ptr, "device-1-no-l3", reinterpret_cast<const char *>(device_1_mac), reinterpret_cast<const char *>(broadcast_mac), 65536,
                              73);
                } else if (ifinfo->ifi_index == 3) {
                    device_2_seen = true;
                    const unsigned char device_3_mac[] = { 0x50, 0xaa, 0x00, 0x00, 0x00, 0x00 };
                    test_link(msg_ptr, "device-2-eth0", reinterpret_cast<const char *>(device_3_mac), reinterpret_cast<const char *>(broadcast_mac), 1500,
                              4163);
                } else if (ifinfo->ifi_index == 4) {
                    device_3_seen = true;
                    const unsigned char device_4_mac[] = { 0x60, 0xaa, 0x00, 0x00, 0x00, 0x00 };
                    test_link(msg_ptr, "device-3-eth1", reinterpret_cast<const char *>(device_4_mac), reinterpret_cast<const char *>(broadcast_mac), 1500,
                              4163);
                } else {
                    nfl_log_fatal("Unknown index");
                    FAIL();
                }
                continue;
            }
            default:
                nfl_log_fatal("Received unknown message type");
                FAIL();
            }
        }
        ASSERT_EQ(len, 0);
    }

    ASSERT_TRUE(device_1_seen);
    ASSERT_TRUE(device_2_seen);
    ASSERT_TRUE(device_3_seen);
    ASSERT_TRUE(device_lo_seen);

    ASSERT_EQ(msg_count, 5);
    close(s);
}
