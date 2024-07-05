#include <gtest/gtest.h>
#include <arpa/inet.h>
#include <fcntl.h>

extern "C" {
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include "../../src/environment/network_env.h"
#include "module.h"
}

class TestTCP : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/tcp1.conf");
    }
};

TEST_F(TestTCP, test_create_tcp_socket_v4) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);
    int type;
    socklen_t type_length = sizeof(type);
    int domain;
    socklen_t domain_length = sizeof(domain);

    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_length), 0);
    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length), 0);
    ASSERT_EQ(domain, AF_INET);
    ASSERT_EQ(type, SOCK_STREAM);
}

TEST_F(TestTCP, test_create_tcp_socket_v6) {
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);
    int type;
    socklen_t type_length = sizeof(type);
    int domain;
    socklen_t domain_length = sizeof(domain);

    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_length), 0);
    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length), 0);
    ASSERT_EQ(domain, AF_INET6);
    ASSERT_EQ(type, SOCK_STREAM);
}

TEST_F(TestTCP, test_bind_accept_send_recv_tcp_socket_v4) {
    //Creating socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);
    struct sockaddr_in local_addr {};

    //Bind
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(4000);
    int res = bind(socket_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    ASSERT_EQ(res, 0);

    struct sockaddr_in local_addr_check {};
    socklen_t local_addr_check_len = sizeof(local_addr_check);
    ASSERT_EQ(getsockname(socket_fd, (struct sockaddr *)&local_addr_check, &local_addr_check_len), 0);
    ASSERT_EQ(local_addr_check.sin_family, AF_INET);
    ASSERT_EQ(local_addr_check.sin_addr.s_addr, htonl(INADDR_ANY));
    ASSERT_EQ(local_addr_check.sin_port, htons(4000));

    struct sockaddr_in remote_addr {};
    socklen_t remote_addr_len = sizeof(local_addr);
    //Can't accept on non-listening socket
    ASSERT_LT(accept(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len), 0);

    //Listen
    int is_listening = -1;
    socklen_t is_listening_len = sizeof(is_listening);

    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_ACCEPTCONN, &is_listening, &is_listening_len), 0);
    ASSERT_EQ(is_listening, 0);
    listen(socket_fd, 1);
    ASSERT_EQ(getsockopt(socket_fd, SOL_SOCKET, SO_ACCEPTCONN, &is_listening, &is_listening_len), 0);
    ASSERT_EQ(is_listening, 1);

    //Accept
    int connected_socket_fd = accept(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len);
    ASSERT_GT(connected_socket_fd, 0);
    ASSERT_EQ(remote_addr.sin_family, AF_INET);
    struct sockaddr_in *remote_addr_v4 = &remote_addr;
    ASSERT_EQ(remote_addr_v4->sin_port, htons(5000));
    ASSERT_STREQ(inet_ntoa(remote_addr.sin_addr), "127.0.0.5");

    //Can't accept on non-listening but connected socket
    ASSERT_LT(accept(connected_socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len), 0);

    int type;
    socklen_t type_length = sizeof(type);
    int domain;
    socklen_t domain_length = sizeof(domain);

    ASSERT_EQ(getsockopt(connected_socket_fd, SOL_SOCKET, SO_TYPE, &type, &type_length), 0);
    ASSERT_EQ(getsockopt(connected_socket_fd, SOL_SOCKET, SO_DOMAIN, &domain, &domain_length), 0);
    ASSERT_EQ(domain, AF_INET);
    ASSERT_EQ(type, SOCK_STREAM);

    //send
    size_t buffer_len = sizeof(char) * 10;
    char *buffer = (char *)malloc(buffer_len);

    ssize_t amount_bytes_sent = send(connected_socket_fd, buffer, buffer_len, 0);
    ASSERT_EQ(amount_bytes_sent, buffer_len);

    //Can't send on non connected socket
    amount_bytes_sent = send(socket_fd, buffer, buffer_len, 0);
    ASSERT_LT(amount_bytes_sent, 0);

    //recv
    ssize_t amount_bytes_received = recv(connected_socket_fd, buffer, buffer_len, 0);
    ASSERT_EQ(amount_bytes_received, 1);
    ASSERT_EQ(buffer[0], 0x05);

    //close
    ASSERT_EQ(close(connected_socket_fd), 0);
    ASSERT_EQ(close(socket_fd), 0);

    //Can't send on closed socket
    amount_bytes_sent = send(connected_socket_fd, buffer, buffer_len, 0);
    ASSERT_EQ(amount_bytes_sent, -1);

    //Can't recv on closed socket
    amount_bytes_received = recv(connected_socket_fd, buffer, buffer_len, 0);
    ASSERT_EQ(amount_bytes_received, -1);

    //Can't accept on closed socket
    ASSERT_LT(accept(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len), 0);

    //Can't getsockname on closed socket
    ASSERT_NE(getsockname(socket_fd, (struct sockaddr *)&local_addr_check, &local_addr_check_len), 0);

    //Can't getpeername on closed socket
    ASSERT_NE(getpeername(socket_fd, (struct sockaddr *)&local_addr_check, &local_addr_check_len), 0);
}

TEST_F(TestTCP, blocking_accept_v4) {
    struct sockaddr_in local_addr {};

    //Bind
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    local_addr.sin_port = htons(4001);

    //Creating socket
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);

    int res = bind(socket_fd, (struct sockaddr *)&local_addr, sizeof(local_addr));
    ASSERT_EQ(res, 0);

    struct sockaddr_in remote_addr {};
    socklen_t remote_addr_len = sizeof(local_addr);
    //Can't accept on non-listening socket
    ASSERT_EQ(accept(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len), -1);
    ASSERT_EQ(listen(socket_fd, 1), 0);
    int flags = fcntl(socket_fd, F_GETFL, 0);
    ASSERT_FALSE(IS_FLAG_SET(flags, SOCK_NONBLOCK));

    ASSERT_EQ(accept4(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len, SOCK_NONBLOCK), -1);
    //NON BLOCK flag should be set now.
    ASSERT_EQ(accept(socket_fd, (struct sockaddr *)&remote_addr, &remote_addr_len), -1);
    flags = fcntl(socket_fd, F_GETFL, 0);
    ASSERT_EQ(flags, SOCK_NONBLOCK);
    ASSERT_EQ(fcntl(socket_fd, F_SETFL, SOCK_NONBLOCK), 0);
    flags = fcntl(socket_fd, F_SETFL, 0);
    ASSERT_EQ(flags, 0);
    //    ASSERT_EXIT(accept(socket_fd, (struct sockaddr *) &remote_addr, &remote_addr_len), testing::ExitedWithCode(0), "");
}

TEST_F(TestTCP, test_connect_v4) {
    int socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in local_addr {
    }, remote_addr{}, remote_addr_fail{};

    //Bind
    remote_addr.sin_family = AF_INET;
    inet_aton("127.0.0.5", &remote_addr.sin_addr);
    remote_addr.sin_port = htons(5000);

    remote_addr_fail.sin_family = AF_INET;
    inet_aton("127.0.0.6", &remote_addr_fail.sin_addr);
    remote_addr_fail.sin_port = htons(5000);

    char buf[10]{};
    ssize_t ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, -1);

    //  ASSERT_EQ(connect(socket_fd, reinterpret_cast<const sockaddr *>(&remote_addr_fail), sizeof(remote_addr_fail)), -1);
    ASSERT_EQ(connect(socket_fd, reinterpret_cast<const sockaddr *>(&remote_addr), sizeof(remote_addr)), 0);

    socklen_t socklen = sizeof(local_addr);
    ASSERT_EQ(getsockname(socket_fd, reinterpret_cast<sockaddr *>(&local_addr), &socklen), 0);
    ASSERT_EQ(local_addr.sin_family, AF_INET);
    ASSERT_STREQ(inet_ntoa(local_addr.sin_addr), "127.0.0.1");

    ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, 3);
    ASSERT_EQ(buf[0], 0x06);
    ASSERT_EQ(buf[1], 0x10);
    ASSERT_EQ(buf[2], '\xAA');

    ret = recv(socket_fd, buf, 2, MSG_DONTWAIT);
    ASSERT_EQ(ret, 0);
    ASSERT_EXIT(read(socket_fd, buf, sizeof(buf)), testing::ExitedWithCode(0), "");
}

TEST_F(TestTCP, test_bind_tcp_socket_v6) {
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);
    struct sockaddr_in6 local_addr {};

    //Bind
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    local_addr.sin6_port = htons(6000);

    int ret = bind(socket_fd, reinterpret_cast<const sockaddr *>(&local_addr), sizeof(local_addr));
    ASSERT_EQ(ret, 0);
}

TEST_F(TestTCP, test_bind_fail_tcp_socket_v6) {
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GT(socket_fd, 0);
    struct sockaddr_in6 local_addr {};

    //Bind
    local_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db88:3333:4444:5555:6666:7777:8888", &local_addr.sin6_addr);
    local_addr.sin6_port = htons(6000);
    int ret = bind(socket_fd, reinterpret_cast<const sockaddr *>(&local_addr), sizeof(local_addr));
    ASSERT_EQ(ret, -1);
}

TEST_F(TestTCP, test_connect_v6) {
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 local_addr {
    }, remote_addr{}, remote_addr_fail{};

    //Bind
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    local_addr.sin6_port = htons(6000);

    remote_addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db88:3333:4444:5555:6666:7777:6666", &remote_addr.sin6_addr);
    remote_addr.sin6_port = htons(7000);

    remote_addr_fail.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "2001:db88:3333:4444:5555:6666:7777:6666", &remote_addr_fail.sin6_addr);
    remote_addr_fail.sin6_port = htons(7001);

    ssize_t ret = bind(socket_fd, reinterpret_cast<const sockaddr *>(&local_addr), sizeof(local_addr));
    ASSERT_EQ(ret, 0);
    char buf[10]{};
    ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, -1);

    ASSERT_EQ(connect(socket_fd, reinterpret_cast<const sockaddr *>(&remote_addr_fail), sizeof(remote_addr_fail)), -1);
    ASSERT_EQ(connect(socket_fd, reinterpret_cast<const sockaddr *>(&remote_addr), sizeof(remote_addr)), 0);

    ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x05);

    ret = recv(socket_fd, buf, 2, 0);
    ASSERT_EQ(ret, 2);
    ASSERT_EQ(buf[0], 0x06);
    ASSERT_EQ(buf[1], 0x10);

    ret = recv(socket_fd, buf, sizeof(buf), 0);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], '\xAA');

    errno = 0;
    int flags = fcntl(socket_fd, F_GETFL, 0);
    ASSERT_EQ(flags, 0);
    ret = recv(socket_fd, buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT_EQ(ret, 0);
    ASSERT_EQ(errno, EAGAIN);
    flags = fcntl(socket_fd, F_GETFL, 0);
    ASSERT_EQ(flags, 0);
    ASSERT_EXIT(recv(socket_fd, buf, sizeof(buf), 0), testing::ExitedWithCode(0), "");
}

TEST_F(TestTCP, test_accept_v6) {
    int socket_fd = socket(AF_INET6, SOCK_STREAM, 0);
    struct sockaddr_in6 local_addr {
    }, remote_addr{};

    //Bind
    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_addr = IN6ADDR_LOOPBACK_INIT;
    local_addr.sin6_port = htons(6000);

    ssize_t ret = bind(socket_fd, reinterpret_cast<const sockaddr *>(&local_addr), sizeof(local_addr));
    ASSERT_EQ(ret, 0);
    char buf[10]{};
    ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, -1);

    socklen_t remote_addr_len = sizeof(remote_addr);
    int connected_fd = accept(socket_fd, reinterpret_cast<sockaddr *>(&remote_addr), &remote_addr_len);
    ASSERT_EQ(connected_fd, -1);
    ASSERT_EQ(listen(socket_fd, 1), 0);
    connected_fd = accept(socket_fd, reinterpret_cast<sockaddr *>(&remote_addr), &remote_addr_len);
    ASSERT_GT(connected_fd, 0);
    ASSERT_EQ(remote_addr.sin6_family, AF_INET6);
    ASSERT_EQ(remote_addr.sin6_port, htons(7001));
    char remote_addr_str[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, &remote_addr.sin6_addr, remote_addr_str, sizeof(remote_addr_str));
    ASSERT_STREQ(remote_addr_str, "2001:db88:3333:4444:5555:6666:7777:8888");

    ret = read(socket_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, -1);

    ret = read(connected_fd, buf, sizeof(buf));
    ASSERT_EQ(ret, 3);
    ASSERT_EQ(buf[0], 0x06);
    ASSERT_EQ(buf[1], 0x10);
    ASSERT_EQ(buf[2], '\xAA');

    ret = recv(connected_fd, buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x05);

    ret = recv(connected_fd, buf, sizeof(buf), MSG_DONTWAIT);
    ASSERT_EQ(ret, 0);

    ASSERT_EXIT(recv(connected_fd, buf, sizeof(buf), 0), testing::ExitedWithCode(0), "");
}