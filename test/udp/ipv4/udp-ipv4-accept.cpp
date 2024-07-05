#include <gtest/gtest.h>

extern "C" {
#include <netfuzzlib/api.h>
#include <sys/fcntl.h>
#include "environment/network_env.h"
}

class TestUDPv4Accept : public ::testing::Test {
protected:
    void SetUp() override {
#ifndef TEST_KERNEL
        init_main_library();
        unsigned int device_index = 0;
        char mac_eth0[ETHER_ADDR_LEN] = { '\x01', '\x02', '\x03', '\x04', '\x05', '\x06' };
        char mac_eth0_brd[ETHER_ADDR_LEN] = { '\xff', '\xff', '\xff', '\xff', '\xff', '\xff' };
        nfl_add_l2_iface("not-a-real-eth0", IFF_MULTICAST | IFF_UP, 65536, mac_eth0, mac_eth0_brd, &device_index);
        nfl_add_l3_iface_ipv4(device_index, "192.168.0.10", "255.255.255.0");
        nfl_set_ipv4_default_gateway("192.168.0.1", device_index);
#endif
    }
#ifdef TEST_KERNEL
    void TearDown() override {
        int socket_type;
        socklen_t length;
        for (int fd = 0; fd < FD_SETSIZE; fd++) {
            socket_type = 0;
            length = sizeof(socket_type);
            if (getsockopt(fd, SOL_SOCKET, SO_TYPE, &socket_type, &length) == -1) {
                continue;
            }
            if (socket_type != SOCK_DGRAM)
                continue;
            close(fd);
        }
    }
#endif
};

/* Test if accept on UDP socket is rejected with ENOTSUP. */
TEST_F(TestUDPv4Accept, accept) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (accept(fd, nullptr, nullptr) >= 0)
        FAIL() << "accept";
    EXPECT_EQ(errno, ENOTSUP);
}

/* Test that a socket being non-blocking has no effect on accept failing with
   ENOTSUP. */
TEST_F(TestUDPv4Accept, nonblock) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0)
        FAIL() << "fcntl";
    if (accept(fd, nullptr, nullptr) >= 0)
        FAIL() << "accept";
    EXPECT_EQ(errno, ENOTSUP);
}