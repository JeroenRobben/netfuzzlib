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

void sigpipe(int sig);

class TestUDPv4Connect : public ::testing::Test {
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

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, send another packet, and send yet another
   packet, and test which send call get the error and if the error is sticky. */
TEST_F(TestUDPv4Connect, send_error_send_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("second send");
    else
        warnx("second send: no error");
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("third send");
    else
        warnx("third send: no error");
}

/* Connect to loopback address port 22897, unconnect, and then test the local
   address. */
TEST_F(TestUDPv4Connect, unconnect_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
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

/* Connect to loopback address port 22897, unconnect, and then test unconnecting
   again. */
TEST_F(TestUDPv4Connect, unconnect_unconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "third connect";
}

/* Connect to a public internet address, send a datagram, then testing
   reconnecting to the loopback address port 22897. */
TEST_F(TestUDPv4Connect, wan_send_reconnect_loopback_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "first send";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char y = 'y';
    if (send(fd, &y, sizeof(y), 0) < 0)
        FAIL() << "second send";
}

/* Connect to the loopback interface port 22897 and then test reconnecting to
   the same address. */
TEST_F(TestUDPv4Connect, reconnect_same) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897 and then test sendto with the same
   address. */
TEST_F(TestUDPv4Connect, sendto_same) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for writing, and then test sending
   a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_w_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "second send";
}

/* Connect to loopback address port 22897, shutdown for writing, unconnect, and
   then test sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_w_unconnect_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_WR))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
}

/* Connect to loopback address port 22897, unconnect, and then test the remote
   address. */
TEST_F(TestUDPv4Connect, unconnect_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
}

/* Connect to the loopback interface port 0 and print the local address. */
TEST_F(TestUDPv4Connect, loopback_0_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to the loopback interface port 22897 and print the local address. */
TEST_F(TestUDPv4Connect, loopback_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, then test if unconnect works if the
   unconnect address is a struct sockaddr_in. */
TEST_F(TestUDPv4Connect, unconnect_sockaddr_in) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(sin));
    cos.sin_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, unconnect, shutdown for reading and
   writing, and then test receiving a datagram. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_rw_recv) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897 and then test sendto with a nullptr
   address parameter. */
TEST_F(TestUDPv4Connect, sendto_null) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, nullptr, 0) < 0)
        FAIL() << "sendto";
}

/* Test connecting to the any address port 22897 and printing the remote
   address. */
TEST_F(TestUDPv4Connect, any_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, get error with SO_ERROR, and then test the poll
   bits. */
TEST_F(TestUDPv4Connect, send_error_poll_so_error_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "first poll";
    if (num_events == 0)
        errx(1, "first poll returned 0");
    printf("first poll: 0");
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
    fflush(stdout);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    errno = errnum;
    if (errnum)
        warn("SO_ERROR");
    else
        warnx("SO_ERROR: no error");
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "second poll";
    if (num_events == 0)
        errx(1, "second poll returned 0");
    printf("second poll: 0");
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

/* Connect to loopback address port 22897, shutdown for reading and writing,
   unconnect, and then test sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_rw_unconnect_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if getpeername delivers the
   asynchronous error. */
TEST_F(TestUDPv4Connect, send_error_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
}

/* Connect to loopback address port 22897, unconnect, shutdown for reading and
   writing, and then test sending a datagram to loopback address port 22897. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_rw_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RDWR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
}

/* Connect to loopback address port 22897, then test if unconnect works if the
   unconnect address is a sa_family_t. */
TEST_F(TestUDPv4Connect, unconnect_sa_family) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    sa_family_t family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&family, sizeof(family)) < 0)
        FAIL() << "second connect";
}

/* Connect to a public internet address, then test the local address. */
TEST_F(TestUDPv4Connect, wan_getsockname) {
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

/* Connect to the loopback address port 22897, then unconnect, and test binding
   to the any address port 0, and then print the local address. */
TEST_F(TestUDPv4Connect, loopback_unconnect_rebind_any_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in foo;
    memset(&foo, 0, sizeof(foo));
    foo.sin_family = AF_INET;
    foo.sin_addr.s_addr = htonl(INADDR_ANY);
    foo.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&foo, sizeof(foo)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Test connecting to the any address port 0 and printing the local address. */
TEST_F(TestUDPv4Connect, any_0_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, shutdown for writing, and then test
   receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_w_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_WR))
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to the loopback address port 22897, and then test reconnecting to the
   loopback address port 65534 and print the local address. */
TEST_F(TestUDPv4Connect, loopback_reconnect_loopback_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    struct sockaddr_in cos {};
    memset(&sin, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "second getsockname";
    char second_port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), second_port, sizeof(second_port), NI_NUMERICHOST | NI_NUMERICSERV);
    if (!strncmp(host, "192.168.", strlen("192.168.")))
        printf("192.168.1.x");
    else if (!strncmp(host, "100.82.", strlen("100.82.")))
        printf("192.168.1.x");
    else
        printf("%s", host);
    printf(":");
    if (!strcmp(port, second_port))
        printf("same port");
    else
        printf("%s", second_port);
    printf("\n");
}

/* Test connecting to the any address port 22897 and printing the local
   address. */
TEST_F(TestUDPv4Connect, any_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, unconnect, shutdown for reading, and
   then test sending a datagram to loopback address port 22897. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_r_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
}

/* Connect to the loopback address port 22897, then test reconnecting to the any
   address port 0 and print the local address. */
TEST_F(TestUDPv4Connect, reconnect_any_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_ANY);
    cos.sin_port = htons(0);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
}

/* Connect to loopback address port 22897, unconnect, shutdown for reading, and
   then test receiving a datagram. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_r_recv) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_RD) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if the poll bits change if poll is
   run twice. */
TEST_F(TestUDPv4Connect, send_error_poll_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    struct pollfd pfd {};
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    int num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "first poll";
    if (num_events == 0)
        errx(1, "first poll returned 0");
    printf("first poll: 0");
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
    memset(&pfd, 0, sizeof(pfd));
    pfd.fd = fd;
    pfd.events = POLLIN | POLLOUT;
    num_events = poll(&pfd, 1, 0);
    if (num_events < 0)
        FAIL() << "second poll";
    if (num_events == 0)
        errx(1, "second poll returned 0");
    printf("second poll: 0");
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

/* Connect to loopback address port 22897 and then test shutdown for reading
   and writing. */
TEST_F(TestUDPv4Connect, shutdown) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if accept delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_accept) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (accept(fd, nullptr, nullptr) >= 0)
        FAIL() << "accept";
}

/* Connect to loopback address port 22897, shutdown for reading and writing, and
   then test reconnecting to loopback address port 65534. */
TEST_F(TestUDPv4Connect, shutdown_reconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading, and then test sending
   a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_r_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "second send";
}

/* Connect to the loopback address port 22897 and then test receiving a
   datagram. */
TEST_F(TestUDPv4Connect, recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to the loopback address port 22897 and test if the socket was bound
   to an interface according to SO_BINDTODEVICE. */
TEST_F(TestUDPv4Connect, loopback_get_so_bindtodevice) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
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

/* Test connecting to the broadcast address port 10000 and printing the remote
   address. */
TEST_F(TestUDPv4Connect, broadcast_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(1);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to a public internet address, and then test if the socket as bound
   to a network interface using SO_BINDTODEVICE.  */
TEST_F(TestUDPv4Connect, wan_get_so_bindtodevice) {
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

/* Connect to the loopback interface port 0 and print the remote address. */
TEST_F(TestUDPv4Connect, loopback_0_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(0);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
}

/* Connect to loopback address port 22897, then test if unconnect works if the
   unconnect address is a struct sockaddr. */
TEST_F(TestUDPv4Connect, unconnect_sockaddr) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(sin));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, and then test unconnecting. */
TEST_F(TestUDPv4Connect, unconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, shutdown for reading and writing, and
   then test receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_rw_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, shutdown for reading, unconnect, and
   then test receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_r_unconnect_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Test setting SO_BROADCAST, connecting to the broadcast address port 1 and
   printing the local address. */
TEST_F(TestUDPv4Connect, broadcast_getsockname_so_broadcast) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_BROADCAST";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(1);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, shutdown for reading, and then test
   receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_r_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Test connecting to the broadcast address port 1 and printing the local
   address. */
TEST_F(TestUDPv4Connect, broadcast_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(1);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   getting the error with SO_ERROR. */
TEST_F(TestUDPv4Connect, send_error_shutdown_rw_so_error) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
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

/* Connect to loopback address port 22897 and then test the poll bits. */
TEST_F(TestUDPv4Connect, poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
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

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading, and then test receiving
   a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_r_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (shutdown(fd, SHUT_RD) < 0)
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if send delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("second send");
    else
        warnx("second send: no error");
}

/* Test setting SO_BROADCAST, connecting to the broadcast address port 1 and
   printing the remote address. */
TEST_F(TestUDPv4Connect, broadcast_getpeername_so_broadcast) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    int enable = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &enable, sizeof(enable)) < 0)
        FAIL() << "setsockopt: SO_BROADCAST";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_BROADCAST);
    sin.sin_port = htons(1);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   receiving a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_rw_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to a public internet address, unconnect, then test rebinding to the
   any address port 0 and printing the remote address. */
TEST_F(TestUDPv4Connect, wan_unconnect_rebind_any_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in foo;
    memset(&foo, 0, sizeof(foo));
    foo.sin_family = AF_INET;
    foo.sin_addr.s_addr = htonl(INADDR_ANY);
    foo.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "bind";
}

/* Connect to loopback address port 22897, then test if unconnect works if the
   unconnect address is a struct sockaddr_sockaddr. */
TEST_F(TestUDPv4Connect, unconnect_sockaddr_storage) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_storage cos;
    memset(&cos, 0, sizeof(cos));
    cos.ss_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, unconnect, shutdown for writing, and
   then test sending a datagram to loopback address port 22897. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_w_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) >= 0)
        FAIL() << "sendto";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, get error with SO_ERROR, send a datagram, expect
   another error, and then test if sending a datagram again receives the second
   error. */
TEST_F(TestUDPv4Connect, send_error_so_error_send_send) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    int errnum;
    socklen_t errnumlen = sizeof(errnum);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &errnum, &errnumlen) < 0)
        FAIL() << "getsockopt: SO_ERROR";
    errno = errnum;
    if (errnum)
        warn("SO_ERROR");
    else
        warnx("SO_ERROR: no error");
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("second send");
    else
        warnx("second send: no error");
    usleep(50000);
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("third send");
    else
        warnx("third send: no error");
}

/* Connect to loopback address port 22897, shutdown for reading and writing,
   unconnect, and then test receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_rw_unconnect_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897 and then test sendto with another
   address (loopback address port 65534). */
TEST_F(TestUDPv4Connect, sendto_other) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "sendto";
}

/* Test connecting to the any address port 0 and printing the local address. */
TEST_F(TestUDPv4Connect, getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to loopback address port 22897 and then test reconnecting to the
   loopback address port 65534. */
TEST_F(TestUDPv4Connect, reconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, reconnect to the loopback address
   port 65534, and then print the local address. */
TEST_F(TestUDPv4Connect, reconnect_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to loopback address port 22897, shutdown for reading and writing, and
   then test sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_rw_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "send";
}

/* Connect to loopback address port 22897, shutdown for writing, unconnect, and
   then test receiving a datagram. */
TEST_F(TestUDPv4Connect, shutdown_w_unconnect_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_WR))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, shutdown for writing, and then test
   sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_w_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_WR))
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "send";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if connect delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_reconnect) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if poll delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_poll) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
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

/* Connect to loopback address port 22897, shutdown for reading and writing,
   reconnect to loopback address port 65534, and then test sending a
   datagram. */
TEST_F(TestUDPv4Connect, shutdown_rw_reconnect_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RDWR))
        FAIL() << "shutdown";
    struct sockaddr_in cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    cos.sin_port = htons(65534);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "send";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if listen delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_listen) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (listen(fd, 1) >= 0)
        FAIL() << "listen";
}

/* Connect to a public internet address, unconnect, then test rebinding to the
   any address port 0 and printing the local address. */
TEST_F(TestUDPv4Connect, wan_unconnect_rebind_same_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    sin.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in assigned;
    socklen_t assignedlen = sizeof(assigned);
    if (getsockname(fd, (struct sockaddr *)&assigned, &assignedlen) < 0)
        FAIL() << "getsockname";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (bind(fd, (const struct sockaddr *)&assigned, sizeof(assigned)) < 0)
        FAIL() << "bind";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "second getsockname";
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

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if getsockname delivers the
   asynchronous error. */
TEST_F(TestUDPv4Connect, send_error_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getsockname";
}

/* Connect to the loopback interface port 22897 and print the remote address. */
TEST_F(TestUDPv4Connect, loopback_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "getpeername";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    printf("%s:%s\n", host, port);
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for writing, and then test receiving
   a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_w_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    if (shutdown(fd, SHUT_WR) < 0)
        FAIL() << "shutdown";
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, shutdown for reading, and then test
   sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_r_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        FAIL() << "send";
}

/* Connect to the loopback address port 22897, and then test reconnecting to the
   public internet and print the local address. */
TEST_F(TestUDPv4Connect, loopback_reconnect_wan_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "first getsockname";
    char host[INET_ADDRSTRLEN + 1];
    char port[5 + 1];
    getnameinfo((const struct sockaddr *)&local, locallen, host, sizeof(host), port, sizeof(port), NI_NUMERICHOST | NI_NUMERICSERV);
    struct sockaddr_in cos {};
    memset(&sin, 0, sizeof(cos));
    cos.sin_family = AF_INET;
    cos.sin_addr.s_addr = htonl(BLACKHOLE_HOST);
    cos.sin_port = htons(BLACKHOLE_PORT);
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) >= 0)
        FAIL() << "second connect";
    if (getsockname(fd, (struct sockaddr *)&local, &locallen) < 0)
        FAIL() << "second getsockname";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, and then test if recv delivers the asynchronous
   error. */
TEST_F(TestUDPv4Connect, send_error_recv) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("send");
    usleep(50000);
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to the loopback address port 22897, then unconnect, and test binding
   to the loopback address port 0, and then print the local address. */
TEST_F(TestUDPv4Connect, loopback_unconnect_rebind_loopback_getsockname) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    struct sockaddr_in foo;
    memset(&foo, 0, sizeof(foo));
    foo.sin_family = AF_INET;
    foo.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    foo.sin_port = htons(0);
    if (bind(fd, (const struct sockaddr *)&foo, sizeof(foo)) < 0)
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
    printf(":");
    if (!strcmp(port, "0"))
        printf("%s", port);
    else
        printf("non-zero");
    printf("\n");
}

/* Connect to loopback address port 22897, unconnect, shutdown for writing, and
   then test receiving a datagram. */
TEST_F(TestUDPv4Connect, unconnect_shutdown_w_recv) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    if (shutdown(fd, SHUT_WR) >= 0)
        FAIL() << "shutdown";
    char x;
    ssize_t amount = recv(fd, &x, sizeof(x), MSG_DONTWAIT);
    if (amount >= 0)
        FAIL() << "recv";
}

/* Connect to loopback address port 22897, shutdown for reading, unconnect, and
   then test sending a datagram. */
TEST_F(TestUDPv4Connect, shutdown_r_unconnect_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "first connect";
    if (shutdown(fd, SHUT_RD))
        FAIL() << "shutdown";
    struct sockaddr cos {};
    memset(&cos, 0, sizeof(cos));
    cos.sa_family = AF_UNSPEC;
    if (connect(fd, (const struct sockaddr *)&cos, sizeof(cos)) < 0)
        FAIL() << "second connect";
    char x = 'x';
    if (sendto(fd, &x, sizeof(x), 0, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "sendto";
}

/* Test connecting to the any address port 0 and printing the remote address. */
TEST_F(TestUDPv4Connect, any_0_getpeername) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_ANY);
    sin.sin_port = htons(0);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    struct sockaddr_in local {};
    socklen_t locallen = sizeof(local);
    if (getpeername(fd, (struct sockaddr *)&local, &locallen) >= 0)
        FAIL() << "getpeername";
}

/* Connect to loopback address port 22897, send a datagram, and expect an ICMP
   connection refused packet, shutdown for reading and writing, and then test
   sending a datagram. */
TEST_F(TestUDPv4Connect, send_error_shutdown_rw_send) {
    signal(SIGPIPE, sigpipe);
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd < 0)
        FAIL() << "socket";
    struct sockaddr_in sin {};
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port = htons(22897);
    if (connect(fd, (const struct sockaddr *)&sin, sizeof(sin)) < 0)
        FAIL() << "connect";
    char x = 'x';
    if (send(fd, &x, sizeof(x), 0) < 0)
        warn("first send");
    usleep(50000);
    if (shutdown(fd, SHUT_RDWR) < 0)
        FAIL() << "shutdown";
    if (send(fd, &x, sizeof(x), 0) >= 0)
        FAIL() << "second send";
}
