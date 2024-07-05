#include <gtest/gtest.h>
#include <netdb.h>

extern "C" {
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
}
#define BLACKHOLE_HOST "8.8.8.8"
#define BLACKHOLE_PORT 53

class TestUDPv4Send : public ::testing::Test {
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

/* Test sending a datagram without a specified destination. */
TEST_F(TestUDPv4Send, sendto_null) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, nullptr, 0) >= 0)
        FAIL() << "sendto";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    if (errnum) {
        errno = errnum;
        FAIL() << "SO_ERROR";
    }
}

/* Test sending a datagram to the any address. */
TEST_F(TestUDPv4Send, sendto_any_so_error) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(65535);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    if (errnum) {
        errno = errnum;
        FAIL() << "SO_ERROR";
    }
}

/* Send a datagram to loopback address port 65535 and then test the local
   address. */
TEST_F(TestUDPv4Send, sendto_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(65535);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (!strncmp(host, "192.168.", strlen("192.168.")))
        printf("192.168.1.x");
    else if (!strncmp(host, "100.82.", strlen("100.82.")))
        printf("192.168.1.x");
    else
        printf("%s", host);
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Test sending a datagram without a specified destination. */
TEST_F(TestUDPv4Send, send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "send";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    if (errnum) {
        errno = errnum;
        FAIL() << "SO_ERROR";
    }
}

/* Test sending a datagram to the loopback address port 0. */
TEST_F(TestUDPv4Send, sendto_loopback_0_so_error) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    if (errnum) {
        errno = errnum;
        FAIL() << "SO_ERROR";
    }
}
