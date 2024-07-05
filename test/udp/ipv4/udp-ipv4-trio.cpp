#include <gtest/gtest.h>
#include "udp-ipv4.h"

extern "C" {
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
}
#define BLACKHOLE_HOST "8.8.8.8"
#define BLACKHOLE_PORT 53

class TestUDPv4Trio : public ::testing::Test {
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

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'x' on the second socket to the
   first socket, and then test if 'x' is received on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_right_x_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, connect the first socket to the second
   socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, send_wrong_y_connect_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, send 'x' on the second socket to the first socket, and then
   test whether 'x' or 'y' is received on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_wrong_y_send_right_x_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'x' on the second socket to the
   first socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_right_x_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, and then test receiving 'x' on the
   first socket. */
TEST_F(TestUDPv4Trio, send_right_x_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, connect the first socket to the second
   socket, and then test if 'y' is received on the first socket. */
TEST_F(TestUDPv4Trio, send_wrong_y_connect_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, send 'x' on the second socket to the first socket, and then
   test the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_wrong_y_send_right_x_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_wrong_y_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, send 'y' on the third socket to the
   first socket, and then test receiving 'x' on the first socket. */
TEST_F(TestUDPv4Trio, send_right_x_send_wrong_y_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, send 'y' on the third socket to the
   first socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, send_right_x_send_wrong_y_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, send 'x' on the second socket to the
   first socket, connect the first socket to the second socket, and then test
   the poll bits on the first socket. */
TEST_F(TestUDPv4Trio, send_wrong_y_connect_send_right_x_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, connect the
   first socket to the second socket, send 'y' on the third socket to the
   first socket, and then test if 'y' is received on the first socket. */
TEST_F(TestUDPv4Trio, connect_send_wrong_y_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(100000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0) {
        perror("recv");
        FAIL() << "recv";
    } else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'x' on
   the second socket to the first socket, and then test the poll bits on the
   first socket. */
TEST_F(TestUDPv4Trio, send_right_x_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "poll";
    if (num_events == 0)
        errx(1, "poll returned 0");
    printf("0");
    if (pfd.revents & POLLIN)
        printf(" | POLLIN");
    if (pfd.revents & POLLPRI)
        printf(" | POLLPRI");
    if (pfd.revents & POLLOUT)
        printf(" | POLLOUT");
#if defined(POLLRDHUP) && POLLRDHUP != POLLHUP
    if (pfd.revents & POLLRDHUP)
        printf(" | POLLRDHUP");
#endif
    if (pfd.revents & POLLERR)
        printf(" | POLLERR");
    if (pfd.revents & POLLHUP)
        printf(" | POLLHUP");
#if POLLRDNORM != POLLIN
    if (pfd.revents & POLLRDNORM)
        printf(" | POLLRDNORM");
#endif
#if POLLRDBAND != POLLPRI
    if (pfd.revents & POLLRDBAND)
        printf(" | POLLRDBAND");
#endif
#if POLLWRNORM != POLLOUT
    if (pfd.revents & POLLWRNORM)
        printf(" | POLLWRNORM");
#endif
#if POLLWRBAND != POLLOUT
    if (pfd.revents & POLLWRBAND)
        printf(" | POLLWRBAND");
#endif
    putchar('\n');
}

/* Create three sockets on the loopback address, connect the second socket to
   the first socket, connect the third socket to the first socket, send 'y' on
   the third socket to the first socket, send 'x' on the second socket to the
   first socket, connect the first socket to the second socket, and then test
   if 'x' or 'y' is received on the first socket. */
TEST_F(TestUDPv4Trio, send_wrong_y_connect_send_right_x_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    int fd3 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd3 < 0)
        FAIL() << "second socket";
    if (bind(fd3, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in local3 {};
    socklen_t locallen3 = sizeof(local3);
    if (getsockname(fd3, (struct sockaddr *)&local3, &locallen3) < 0)
        FAIL() << "second getsockname";
    if (connect(fd3, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char y = 'y';
    if (send(fd3, &y, sizeof(y), 0) < 0)
        FAIL() << "send of y";
    usleep(50000);
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send of x";
    usleep(50000);
    char z;
    ssize_t amount = recv(fd, &z, sizeof(z), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (z == 'x' || z == 'y')
        printf("%c\n", z);
    else
        printf("recv wrong byte");
}
