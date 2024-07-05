#include <gtest/gtest.h>
#include "udp-ipv4.h"

extern "C" {
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
}

void sigpipe(int sig) {
    printf("Caught signal %d\n", sig);
}

class TestUDPv4Shutdown : public ::testing::Test {
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

/* Test shutdown for read and write on a freshly made socket. */
TEST_F(TestUDPv4Shutdown, shutdown) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
}

/* Shut down for writing and then test receiving a datagram. */
TEST_F(TestUDPv4Shutdown, w_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Shut down for reading and then test sending a datagram. */
TEST_F(TestUDPv4Shutdown, r_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
}

/* Shut down for reading and writing and then test sending a datagram. */
TEST_F(TestUDPv4Shutdown, rw_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0) {
        FAIL() << "sendto";
    }
}

/* Shut down for writing and then test sending a datagram. */
TEST_F(TestUDPv4Shutdown, w_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
}

/* Shut down for reading and then test receiving a datagram. */
TEST_F(TestUDPv4Shutdown, r_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Shut down for reading and writing and then test receiving a datagram. */
TEST_F(TestUDPv4Shutdown, rw_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
}
