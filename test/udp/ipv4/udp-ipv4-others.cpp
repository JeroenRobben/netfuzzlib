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

class TestUDPv4Others : public ::testing::Test {
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

/* Unconnect a freshly made socket and test its local address. */
TEST_F(TestUDPv4Others, unconnect_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "unconnect";
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

/* Unconnect a freshly made socket and test its remote address. */
TEST_F(TestUDPv4Others, unconnect_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "unconnect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
}

/* Test sending from the loopback network to the internet. */
TEST_F(TestUDPv4Others, cross_netif_loopback_send_lan_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
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
    close(fd);
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "first bind";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    struct sockaddr_in tan {};
    memset(&tan, 0, sizeof(tan));
    tan.sin_family = AF_INET;
    tan.sin_addr.s_addr = local.sin_addr.s_addr;
    tan.sin_port = htons(0);
    if (bind(fd2, (const struct sockaddr *)&tan, sizeof(tan)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in fd2addr;
    socklen_t fd2addrlen = sizeof(fd2addr);
    if (getsockname(fd2, (struct sockaddr *)&fd2addr, &fd2addrlen) < 0)
        FAIL() << "second getsockname";
    char x = 'x';
    if (sendto(fd1, &x, sizeof(x), 0, (const struct sockaddr *)&fd2addr, sizeof(fd2addr)) < 0)
        FAIL() << "sendto";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd1, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    errno = errnum;
    if (errnum)
        FAIL() << "SO_ERROR";
    struct sockaddr_in sender {};
    socklen_t senderlen = sizeof(sender);
    char c;
    ssize_t amount = recvfrom(fd2, &c, sizeof(c), MSG_DONTWAIT, (struct sockaddr *)&sender, &senderlen);
    if (amount < 0)
        FAIL() << "recvfrom";
    else if (amount == 0)
        errx(1, "recvfrom: EOF");
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&sender, senderlen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
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
    printf(": ");
    if (amount != 1)
        printf("recv %zi bytes", amount);
    else if (c == 'x')
        putchar(x);
    else
        printf("recv wrong byte");
    putchar('\n');
}

/* Receive a datagram on a freshly made socket and then test the local
   address. */
TEST_F(TestUDPv4Others, recvfrom_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    socklen_t sinlen = sizeof(sin);
    char x;
    if (recvfrom(fd, &x, sizeof(x), MSG_DONTWAIT, (struct sockaddr *)&sin, &sinlen) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            FAIL() << "recvfrom";
    }
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

/* Test sending from the internet to the loopback network. */
TEST_F(TestUDPv4Others, cross_netif_lan_send_loopback_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
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
    close(fd);
    int fd1 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd1 < 0)
        FAIL() << "first socket";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = local.sin_addr.s_addr;
    cos.sin_port = htons(0);
    if (bind(fd1, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "first bind";
    int fd2 = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd2 < 0)
        FAIL() << "second socket";
    struct sockaddr_in tan {};
    memset(&tan, 0, sizeof(tan));
    tan.sin_family = AF_INET;
    tan.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    tan.sin_port = htons(0);
    if (bind(fd2, (const struct sockaddr *)&tan, sizeof(tan)) < 0)
        FAIL() << "second bind";
    struct sockaddr_in fd2addr;
    socklen_t fd2addrlen = sizeof(fd2addr);
    if (getsockname(fd2, (struct sockaddr *)&fd2addr, &fd2addrlen) < 0)
        FAIL() << "second getsockname";
    char x = 'x';
    if (sendto(fd1, &x, sizeof(x), 0, (const struct sockaddr *)&fd2addr, sizeof(fd2addr)) < 0)
        FAIL() << "sendto";
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd1, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    errno = errnum;
    if (errnum)
        FAIL() << "SO_ERROR";
    struct sockaddr_in sender {};
    socklen_t senderlen = sizeof(sender);
    char c;
    ssize_t amount = recvfrom(fd2, &c, sizeof(c), MSG_DONTWAIT, (struct sockaddr *)&sender, &senderlen);
    if (amount < 0)
        FAIL() << "recvfrom";
    else if (amount == 0)
        errx(1, "recvfrom: EOF");
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&sender, senderlen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
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
    printf(": ");
    if (amount != 1)
        printf("recv %zi bytes", amount);
    else if (c == 'x')
        putchar(x);
    else
        printf("recv wrong byte");
    putchar('\n');
}

/* Test the local address of a freshly made socket. */
TEST_F(TestUDPv4Others, getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
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

/* Test whether a freshly made socket is bound to a device according to
   SO_BINDTODEVICE. */
TEST_F(TestUDPv4Others, get_so_bindtodevice) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
#ifdef SO_BINDTODEVICE
    char ifname[IF_NAMESIZE + 1];
    socklen_t ifnamelen = sizeof(ifname);
    if (getsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, ifname, &ifnamelen) < 0)
        FAIL() << "getsockopt: SO_BINDTODEVICE";
    ifname[ifnamelen] = '\0';
    puts(ifname);
#else
    errno = ENOSYS;
    FAIL() << "getsockopt: SO_BINDTODEVICE";
#endif
}

/* Test unconnecting a freshly made socket. */
TEST_F(TestUDPv4Others, unconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "unconnect";
}

/* Test poll bits on a freshly made socket. */
TEST_F(TestUDPv4Others, poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
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

/* Test SO_ERROR on a freshly made socket. */
TEST_F(TestUDPv4Others, so_error) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    errno = errnum;
    if (errnum)
        warn("SO_ERROR");
    else
        warnx("SO_ERROR: no error");
}

/* Test remote address on freshly made socket. */
TEST_F(TestUDPv4Others, getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Test if listen fails with ENOTSUP. */
TEST_F(TestUDPv4Others, listen) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    if (listen(fd, 1) >= 0)
        FAIL() << "listen";
}
