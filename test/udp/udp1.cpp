#include <cerrno>
#include <netinet/in.h>
#include <cstdio>
#include <cstdlib>
#include <sys/types.h>

#include <gtest/gtest.h>
#include <arpa/inet.h>

extern "C" {
#include <netfuzzlib/module_api.h>
#include "module.h"
#include "environment/network_env.h"
}

class TestUDP1 : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/udp.conf");
    }
};

// Test creation of ipv4 udp socket
TEST_F(TestUDP1, test_create_socket_ipv4) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(socket_fd, 0);
    int type;
    socklen_t type_length = sizeof(type);
    int domain;
    socklen_t domain_length = sizeof(domain);

    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_length), 0);
    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length), 0);
    ASSERT_EQ(domain, AF_INET);
    ASSERT_EQ(type, SOCK_DGRAM);
}

//Test creation of ipv6 udp socket
TEST_F(TestUDP1, test_create_socket_ipv6) {
    int socket_fd = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GE(socket_fd, 0);

    int type;
    socklen_t type_length = sizeof(type);
    int domain;
    socklen_t domain_length = sizeof(domain);

    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_length), 0);
    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length), 0);
    ASSERT_EQ(domain, AF_INET6);
    ASSERT_EQ(type, SOCK_DGRAM);
}

//Creating an ipv4/ipv6 udp socket should fail when giving tcp as used protocol
TEST_F(TestUDP1, test_create_dgram_socket_with_tcp) {
    int socket_fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_TCP);
    ASSERT_EQ(socket_fd, -1);
    ASSERT_EQ(errno, EPROTONOSUPPORT);

    socket_fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP);
    ASSERT_EQ(socket_fd, -1);
    ASSERT_EQ(errno, EPROTONOSUPPORT);
}

TEST_F(TestUDP1, test_bind) {
    struct sockaddr_in bind_addr, socket_addr;

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(socket_fd, 0);

    bind_addr.sin_family = AF_INET;
    bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_addr.sin_port = htons(5000);

    int res = bind(socket_fd, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in));
    assert(res == 0);

    socklen_t addrlen = sizeof(struct sockaddr_in);
    /* get the local address of the connected socket */
    res = getsockname(socket_fd, (struct sockaddr *)&socket_addr, &addrlen);
    ASSERT_EQ(res, 0);
    ASSERT_EQ(addrlen, sizeof(struct sockaddr_in));
    ASSERT_EQ(socket_addr.sin_family, AF_INET);
    ASSERT_EQ(socket_addr.sin_addr.s_addr, htonl(INADDR_ANY));
    ASSERT_EQ(socket_addr.sin_port, htons(5000));
}

TEST_F(TestUDP1, test_bind_unknown_address) {
    struct sockaddr_in bind_addr {};

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(socket_fd, 0);

    bind_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "192.168.1.2", &bind_addr.sin_addr);
    bind_addr.sin_port = htons(5000);

    int res = bind(socket_fd, (struct sockaddr *)&bind_addr, sizeof(struct sockaddr_in));
    ASSERT_NE(res, 0);
    socklen_t socklen = sizeof(struct sockaddr_in);
    res = getsockname(socket_fd, (struct sockaddr *)&bind_addr, &socklen);
    ASSERT_NE(res, 0);
}

TEST_F(TestUDP1, test_dgram_receive_queue_test_1) {
    struct sockaddr_in local_addr;

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    ASSERT_GE(socket_fd, 0);

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(5000);

    int res = bind(socket_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    ASSERT_GE(res, 0);
    int flags = 0;
    char *buffer = static_cast<char *>(malloc(sizeof(char)));

    ssize_t bytes_received = recv(socket_fd, buffer, sizeof(char), 0);

    ASSERT_EQ(bytes_received, 1);
    ASSERT_EQ(buffer[0], '\x12');

    free(buffer);
    int test_field_len = sizeof(uint32_t);
    buffer = static_cast<char *>(malloc(test_field_len));
    bytes_received = recv(socket_fd, buffer, 2, MSG_PEEK | MSG_TRUNC);
    ASSERT_EQ(bytes_received, 4);
    bytes_received = recv(socket_fd, buffer, 2, MSG_PEEK);
    ASSERT_EQ(bytes_received, 2);
    bytes_received = recv(socket_fd, buffer, test_field_len, 0);
    ASSERT_EQ(bytes_received, 4);

    auto *val = (uint32_t *)buffer;
    ASSERT_EQ(ntohl(*val), 1111111);
    free(buffer);

    ASSERT_EQ(recv(socket_fd, buffer, test_field_len, MSG_DONTWAIT), 0);
    ASSERT_EXIT(recv(socket_fd, buffer, test_field_len, 0), testing::ExitedWithCode(0), "");
}

TEST_F(TestUDP1, test_dgram_receive_queue_test_recvmsg) {
    struct sockaddr_in local_addr {};

    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);

    ASSERT_GE(socket_fd, 0);

    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(5000);

    int ret = bind(socket_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    ASSERT_EQ(ret, 0);
    const int on = 1;
    ret = setsockopt(socket_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    ASSERT_EQ(ret, 0);
    int val = -1;
    socklen_t val_len = sizeof(int);
    ret = getsockopt(socket_fd, IPPROTO_IP, IP_PKTINFO, (void *)&val, &val_len);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(val, 0);

    struct msghdr my_msghdr = {};
    struct iovec iov = {};
    struct sockaddr_in msg_name_buffer = {};
    iov.iov_base = calloc(1, 2000);
    iov.iov_len = 2000;

    my_msghdr.msg_name = &msg_name_buffer;
    my_msghdr.msg_namelen = sizeof(struct sockaddr_in);
    my_msghdr.msg_control = calloc(1, 1000);
    my_msghdr.msg_controllen = 1000;
    my_msghdr.msg_iov = &iov;
    my_msghdr.msg_iovlen = 1;

    ssize_t bytes_received = recvmsg(socket_fd, &my_msghdr, 0);
    ASSERT_EQ(bytes_received, 11);

    cmsghdr *cmsg;
    bool ip_pktinfo_seen = true;
    for (cmsg = CMSG_FIRSTHDR(&my_msghdr); cmsg; cmsg = CMSG_NXTHDR(&my_msghdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pktinfo = ((struct in_pktinfo *)CMSG_DATA(cmsg));
            ASSERT_EQ(pktinfo->ipi_ifindex, 1);
            ASSERT_STREQ(inet_ntoa(pktinfo->ipi_addr), "127.0.0.1");
            ip_pktinfo_seen = true;
        }
    }
    ASSERT_TRUE(ip_pktinfo_seen);

    sockaddr_in remote_addr_correct = {};
    remote_addr_correct.sin_family = AF_INET;
    remote_addr_correct.sin_port = htons(5001);
    inet_pton(AF_INET, "127.0.0.2", &remote_addr_correct.sin_addr);
    ASSERT_EQ(memcmp(&msg_name_buffer, &remote_addr_correct, sizeof(sockaddr_in)), 0);
}

TEST_F(TestUDP1, udp_queue_test_2) {
    int fd;
    struct sockaddr_in6 local_addr, remote_addr;
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GT(fd, 0);
    memset(&local_addr, 0, sizeof(struct sockaddr_in6));
    memset(&remote_addr, 0, sizeof(struct sockaddr_in6));

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(6000);

    inet_pton(AF_INET6, "::1", &local_addr.sin6_addr);
    int res = bind(fd, (struct sockaddr *)&local_addr, sizeof(struct sockaddr_in6));
    ASSERT_EQ(res, 0);

    ssize_t n;
    socklen_t len = sizeof(struct sockaddr_in6);
    char buffer[2000];
    n = recvfrom(fd, buffer, 2000, MSG_WAITALL, (struct sockaddr *)&remote_addr, &len);
    ASSERT_EQ(n, 7);
    ASSERT_EQ(buffer[0], 100);

    ASSERT_EQ(buffer[1], 0);
    ASSERT_EQ(buffer[2], 0);

    uint32_t *val_3_network = (uint32_t *)&buffer[sizeof(uint8_t) + sizeof(uint16_t)];
    uint32_t val_3 = ntohl(*val_3_network);
    ASSERT_EQ(val_3, 123456);

    struct sockaddr_in6 remote_addr_correct = {};
    remote_addr_correct.sin6_family = AF_INET6;
    remote_addr_correct.sin6_port = htons(6001);
    inet_pton(AF_INET6, "::2", &remote_addr_correct.sin6_addr);

    ASSERT_EQ(memcmp(&remote_addr, &remote_addr_correct, sizeof(struct sockaddr_in6)), 0);

    close(fd);
}