#include <gtest/gtest.h>
#include "udp-ipv4.h"

extern "C" {
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
}

class TestUDPv4Pair : public ::testing::Test {
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

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, send_shutdown_r_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading and writing, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, send_shutdown_rw_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   writing, and then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Pair, send_shutdown_w_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, send a datagram from the second socket
   to the first socket, and then receive a datagram on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_rw_send_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, and then test the poll bits on
   the first socket. */
TEST_F(TestUDPv4Pair, send_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
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

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   writing, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, send_shutdown_w_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_r_send_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
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

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading, and then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Pair, send_shutdown_r_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, shutdown the first socket for
   reading and writing, and then test receiving a datagram on the first
   socket. */
TEST_F(TestUDPv4Pair, send_shutdown_rw_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, send a datagram
   from the second socket to the first socket, and then test receiving a
   datagram on the first socket. */
TEST_F(TestUDPv4Pair, send_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, and then test
   the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_r_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading, send a datagram from the second socket to the first
   socket, and then receive a datagram on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_r_send_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, send a datagram from the second socket to the first
   socket, and then receive a datagram on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_w_send_recv) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "recv";
    else if (amount == 0)
        puts("EOF");
    else if (amount != 1)
        printf("recv %zi bytes\n", amount);
    else if (x != 'x')
        printf("recv wrong byte");
    else
        printf("%c\n", x);
}

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, and then test the poll bits on the
   first socket. */
TEST_F(TestUDPv4Pair, shutdown_rw_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_w_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for reading and writing, send a datagram from the second socket
   to the first socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_rw_send_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
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

/* Create two loopback address sockets connected to each other, shutdown the
   first socket for writing, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Pair, shutdown_w_send_poll) {
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
    struct sockaddr_in local2 {};
    socklen_t locallen2 = sizeof(local2);
    if (getsockname(fd2, (struct sockaddr *)&local2, &locallen2) < 0)
        FAIL() << "second getsockname";
    if (connect(fd, (const struct sockaddr *)&local2, locallen2) < 0)
        FAIL() << "first connect";
    if (connect(fd2, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd2, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
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
