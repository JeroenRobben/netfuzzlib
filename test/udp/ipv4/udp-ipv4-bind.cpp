#include <gtest/gtest.h>
#include <netdb.h>
#include "udp-ipv4.h"

extern "C" {
#include <netfuzzlib/api.h>
#include "environment/network_env.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
}

class TestUDPv4Bind : public ::testing::Test {
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

/* Test binding to the broadcast address in the lan subnet. */
TEST_F(TestUDPv4Bind, lan_subnet_broadcast) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    in_addr_t address = ntohl(local.sin_addr.s_addr);
    in_addr_t subnetmask = 0;
    if ((address & 0xFF000000) == 0x0A000000)
        subnetmask = 0xFFFFF000; // /20
    else if ((address & 0xFFF00000) == 0xAC100000)
        subnetmask = 0xFFF00000; // /12
    else if ((address & 0xFFFF0000) == 0xC0A80000)
        subnetmask = 0xFFFFFF00; // /24
    else if ((address & 0xFFFF8000) == 0x64528000)
        subnetmask = 0xFFFF8000; // /17
    else
        errx(1, "couldn't deduce local area subnet of: %u.%u.%u.%u", address >> 24 & 0xFF, address >> 16 & 0xFF, address >> 8 & 0xFF, address >> 0 & 0xFF);
    in_addr_t target_address = address | ~subnetmask;
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    struct sockaddr_in cos {};
    memset(&sin, 0, sizeof(sin));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(target_address);
    cos.sin_port = htons(0);
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "bind";
}

/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_broadcast_loopback_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_broadcast_broadcast) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Bind to loopback address port 0 and print the local address. */
TEST_F(TestUDPv4Bind, loopback_0_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
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
    putchar(':');
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for writing, and
   then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_w_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_WR) >= 0)
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

/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_broadcast_loopback) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the broadcast address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_broadcast_loopback_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and any address will
    conflict. */
TEST_F(TestUDPv4Bind, conflict_any_any) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for writing, and
   then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_w_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_WR) >= 0)
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

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading, send a datagram from the second socket to the first socket, and
   then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_r_sendto_first_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, and then test receiving a datagram. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_rw_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR))
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

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, then test receiving a datagram on the first
   socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding to the broadcast address port 0 and print the remote address. */
TEST_F(TestUDPv4Bind, broadcast_0_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", port, port);
}

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_loopback_loopback) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and any address will
    conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_any_any_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_any_loopback) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading and writing, send a datagram from the second socket to the first
   socket, and then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_rw_sendto_first_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding to the broadcast address port 0 and print the local address. */
TEST_F(TestUDPv4Bind, broadcast_0_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
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
    putchar(':');
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading and
   writing, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_rw_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) >= 0)
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

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_loopback_broadcast) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading, send a datagram from the second socket to the first socket, and
   then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_r_sendto_first_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, receive a datagram, and then test receiving another datagram. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_rw_recv_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "first recv";
    else if (amount == 0)
        errx(1, "first recv: EOF");
    else if (amount != 1)
        errx(1, "first recv: %zi bytes\n", amount);
    else if (x != 'x')
        errx(1, "first recv: wrong byte");
    else
        printf("first recv: %c\n", x);
    fflush(stdout);
    amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "second recv";
}

/* Test what the local address is after binding to the any address port 0. */
TEST_F(TestUDPv4Bind, any_0_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
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
    putchar(':');
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   writing, send a datagram from the second socket to the first socket, and
   then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_w_sendto_first_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test whether binding to the same port on the loopback address and any address
   will conflict. */
TEST_F(TestUDPv4Bind, conflict_loopback_any) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the broadcast address and any
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_broadcast_any_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, and then test if it can be connected to. */
TEST_F(TestUDPv4Bind, connect_self) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
}

/* Bind to the any address port 0 and test if binding to AF_UNSPEC unbinds the
   socket. */
TEST_F(TestUDPv4Bind, any_0_unbind) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_UNSPEC;
    if (bind(fd, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "bind AF_UNSPEC";
}

/* Bind to loopback port 0, send a datagram to the same socket, and then
   test receiving a datagram. */
TEST_F(TestUDPv4Bind, sendto_self_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test that it works to bind to the any address with port 0. */
TEST_F(TestUDPv4Bind, any_0) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, send a datagram to the same socket, and then test if the
   datagram can be received. */
TEST_F(TestUDPv4Bind, connect_self_send_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test whether binding to the same port on the broadcast address and any
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_broadcast_any) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   and then test receiving a datagram. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_r_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RD))
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

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding to the first address in the lan subnet. */
TEST_F(TestUDPv4Bind, lan_subnet_first) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    in_addr_t address = ntohl(local.sin_addr.s_addr);
    in_addr_t subnetmask = 0;
    if ((address & 0xFF000000) == 0x0A000000)
        subnetmask = 0xFFFFF000; // /20
    else if ((address & 0xFFF00000) == 0xAC100000)
        subnetmask = 0xFFF00000; // /12
    else if ((address & 0xFFFF0000) == 0xC0A80000)
        subnetmask = 0xFFFFFF00; // /24
    else if ((address & 0xFFFF8000) == 0x64528000)
        subnetmask = 0xFFFF8000; // /17
    else
        errx(1, "couldn't deduce local area subnet of: %u.%u.%u.%u", address >> 24 & 0xFF, address >> 16 & 0xFF, address >> 8 & 0xFF, address >> 0 & 0xFF);
    in_addr_t target_address = address & subnetmask;
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    struct sockaddr_in cos {};
    memset(&sin, 0, sizeof(sin));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(target_address);
    cos.sin_port = htons(0);
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "bind";
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading, and
   then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_r_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_RD) >= 0)
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

/* Bind to loopback address port 0 and print the remote address. */
TEST_F(TestUDPv4Bind, loopback_0_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getsockname";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", port, port);
}

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_loopback_broadcast_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading
   and writing, and then test the poll bits set. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_rw_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR))
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

/* Test whether binding to the same port on the any address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_any_broadcast_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test binding to a wrong address (neither the first address, the local
   address, nor the last/broadcast address) in the lan subnet. */
TEST_F(TestUDPv4Bind, lan_subnet_wrong) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    in_addr_t address = ntohl(local.sin_addr.s_addr);
    in_addr_t subnetmask = 0;
    if ((address & 0xFF000000) == 0x0A000000)
        subnetmask = 0xFFFFF000; // /20
    else if ((address & 0xFFF00000) == 0xAC100000)
        subnetmask = 0xFFF00000; // /12
    else if ((address & 0xFFFF0000) == 0xC0A80000)
        subnetmask = 0xFFFFFF00; // /24
    else if ((address & 0xFFFF8000) == 0x64528000)
        subnetmask = 0xFFFF8000; // /17
    else
        FAIL() << "couldn't deduce local area subnet of: %u.%u.%u.%u";
    in_addr_t target_address = (address & subnetmask) + 1;
    if (target_address == address)
        target_address = (address & subnetmask) + 2;
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    struct sockaddr_in cos {};
    memset(&sin, 0, sizeof(sin));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(target_address);
    cos.sin_port = htons(0);
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, shutdown for reading, and then send a
   datagram to itself. */
TEST_F(TestUDPv4Bind, connect_self_shutdown_r_send_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
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
        FAIL() << "poll returned 0";
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

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_loopback_loopback_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Bind to loopback port 0 and test sending a datagram to the same socket. */
TEST_F(TestUDPv4Bind, sendto_self) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   and then test the poll bits set. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_r_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RD))
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

/* Test whether binding to the same port on the loopback address and any address
   will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_loopback_any_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_any_broadcast_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the loopback address and any address
   will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_loopback_any_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_broadcast_broadcast_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_any_loopback_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the broadcast address and broadcast
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_broadcast_broadcast_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test binding to another address in the loopback network. */
TEST_F(TestUDPv4Bind, loopback_other) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
}

/* Test if a socket can be bound twice. */
TEST_F(TestUDPv4Bind, rebind) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "second bind";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, and then test if a datagram can be send to the socket's
   own address. */
TEST_F(TestUDPv4Bind, connect_self_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
}

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, shutdown for reading, send a datagram
   to itself, and then test receiving a datagram. */
TEST_F(TestUDPv4Bind, connect_self_shutdown_r_send_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
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

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, send a datagram to the same socket, and then test the
   poll status bits on the socket. */
TEST_F(TestUDPv4Bind, connect_self_send_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   reading and writing, send a datagram from the second socket to the first
   socket, and then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_rw_sendto_first_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Bind to loopback port 0, make another socket, shutdown the first socket for
   writing, send a datagram from the second socket to the first socket, and
   then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_shutdown_w_sendto_first_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
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

/* Test binding on any address port 0, use getsockname to bind the address
   actually bound to, connect to itself, send a datagram, shutdown for reading,
   receive a datagram, and then test receiving another datagram. */
TEST_F(TestUDPv4Bind, connect_self_send_shutdown_r_recv_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    if (connect(fd, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
    usleep(50000);
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount < 0)
        FAIL() << "first recv";
    else if (amount == 0)
        errx(1, "first recv: EOF");
    else if (amount != 1)
        errx(1, "first recv: %zi bytes\n", amount);
    else if (x != 'x')
        errx(1, "first recv: wrong byte");
    else
        printf("first recv: %c\n", x);
    fflush(stdout);
    amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "second recv";
}

/* Test whether binding to the same port on the loopback address and broadcast
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_loopback_broadcast_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test binding to the loopback network broadcast address. */
TEST_F(TestUDPv4Bind, loopback_broadcast) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = 0;
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
}

/* Test whether binding to the same port on the broadcast address and any
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_broadcast_any_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading, and
   then test the poll bits on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_r_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events == 0)
        FAIL() << "poll returned 0";
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

/* Test whether binding to the same port on the loopback address and loopback
   address will conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_loopback_loopback_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and broadcast
   address will conflict. */
TEST_F(TestUDPv4Bind, conflict_any_broadcast) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and any address will
    conflict when SO_REUSEADDR is passed on the second socket. */
TEST_F(TestUDPv4Bind, conflict_any_any_so_reuseaddr) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    int enable = 1;
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second bind";
}

/* Test whether binding to the same port on the any address and loopback
   address will conflict when SO_REUSEADDR is passed on both sockets. */
TEST_F(TestUDPv4Bind, conflict_any_loopback_so_reuseaddr_both) {
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    int enable = 1;
    if (setsockopt(fd1, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "first setsockopt: SO_REUSEADDR";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first bind";
    struct sockaddr_in cos {};
    socklen_t coslen = sizeof(cos);
    if (getsockname(fd1, (struct sockaddr *)&cos, &coslen) < 0)
        FAIL() << "getsockname";
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    if (setsockopt(fd2, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(enable)) < 0)
        FAIL() << "second setsockopt: SO_REUSEADDR";
    if (bind(fd2, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second bind";
}

/* Test what the remote address is after binding to the any address port 0. */
TEST_F(TestUDPv4Bind, any_0_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getsockname";
}

/* Bind to loopback port 0, make another socket, send a packet from the second
   socket to the first socket, shutdown the first socket for reading and
   writing, and then test receiving a datagram on the first socket. */
TEST_F(TestUDPv4Bind, socket_sendto_first_shutdown_rw_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "socket";
    char x = 'x';
    if (sendto(fd2, &x, sizeof(x), 0, (const struct sockaddr *)&local, locallen) < 0)
        FAIL() << "sendto";
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) >= 0) {
        FAIL() << "shutdown";
    }
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
