#include <gtest/gtest.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
#include "sockets/sockets_util.h"
#include "environment/network_env.h"
#include "module.h"
};

class TestRouting : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/routing-gateway.conf");
    }
};

static void test_udp_connect_ipv4(const char *addr_to_connect, const char *expected_bound_addr) {
    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in addr {};
    addr.sin_family = AF_INET;
    inet_aton(addr_to_connect, &addr.sin_addr);
    addr.sin_port = htons(53);

    //Sets the default remote endpoint of the UDP socket
    //This will be used when e.g. calling write()
    int err = connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    ASSERT_EQ(err, 0);

    struct sockaddr_in bound_address {};
    socklen_t size = sizeof(struct sockaddr_in);
    getsockname(fd, reinterpret_cast<sockaddr *>(&bound_address), &size);
    char *addr_string = inet_ntoa(bound_address.sin_addr);
    ASSERT_STREQ(addr_string, expected_bound_addr);
    close(fd);
}

static void test_udp_connect_ipv6(const char *addr_to_connect, const char *expected_bound_addr) {
    int fd = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);

    struct sockaddr_in6 addr {};
    addr.sin6_family = AF_INET6;
    inet_pton(AF_INET6, addr_to_connect, &addr.sin6_addr);
    addr.sin6_port = htons(53);

    //Sets the default remote endpoint of the UDP socket
    //This will be used when e.g. calling write()
    int err = connect(fd, reinterpret_cast<const sockaddr *>(&addr), sizeof(addr));
    ASSERT_EQ(err, 0);

    struct sockaddr_in6 bound_address {};
    socklen_t size = sizeof(struct sockaddr_in6);
    getsockname(fd, reinterpret_cast<sockaddr *>(&bound_address), &size);
    char addr_string[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &bound_address.sin6_addr, addr_string, INET6_ADDRSTRLEN);
    ASSERT_STREQ(addr_string, expected_bound_addr);
    close(fd);
}

TEST_F(TestRouting, test_udp_ipv4_connect) {
    test_udp_connect_ipv4("127.0.0.5", "127.0.0.1");
    test_udp_connect_ipv4("127.1.0.5", "127.0.0.1");
    test_udp_connect_ipv4("10.0.0.10", "10.0.0.5");
    test_udp_connect_ipv4("10.0.0.5", "10.0.0.5");
    test_udp_connect_ipv4("192.168.1.10", "192.168.1.2");
    test_udp_connect_ipv4("192.168.1.2", "192.168.1.2");
    test_udp_connect_ipv4("192.168.10.1", "10.0.0.5");
    test_udp_connect_ipv4("91.34.10.2", "91.34.10.2");
    test_udp_connect_ipv4("8.8.8.8", "10.0.0.5");
}

TEST_F(TestRouting, test_udp_ipv6_connect) {
    test_udp_connect_ipv6("::1", "::1");
    test_udp_connect_ipv6("2a02::3183:a900:5b63:0019:ab00:c679", "2a02:0:3183:a900:5b63:19:ab00:c679");
    test_udp_connect_ipv6("2a02::3183:a900:5b63:0019:ab00:c680", "2a02:0:3183:a900:5b63:19:ab00:c679");
    test_udp_connect_ipv6("2a02::3183:a900:5b64:0019:ab00:c681", "2a02:0:3183:a900:5b63:19:ab00:c679");
    test_udp_connect_ipv6("2a02::3183:a900:5b63:0020:ab00:c679", "2a02:0:3183:a900:5b63:19:ab00:c679");
    test_udp_connect_ipv6("2a02::3183:a900:5b63:0020:ab00:c679", "2a02:0:3183:a900:5b63:19:ab00:c679");

    test_udp_connect_ipv6("fe80::5859:71af:177e:db7a", "fe80::5859:71af:177e:db7a");
    test_udp_connect_ipv6("fe80::5859:71af:177e:db8a", "fe80::5859:71af:177e:db7a");
    test_udp_connect_ipv6("fe80::5859:72af:177e:db7a", "fe80::5859:71af:177e:db7a");
}

TEST_F(TestRouting, ipv6_addr_within_subnet) {
    struct in6_addr addr1;
    struct in6_addr addr2;
    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7334", &addr1);
    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0100:8a2e:0370:7334", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 128, &addr1));
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 128, &addr2));
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 64, &addr2));
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 72, &addr2));

    inet_pton(AF_INET6, "2000:0000:0000:0000:0000:0000:0000:0000", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 10, &addr2));
    inet_pton(AF_INET6, "203f:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 10, &addr2));
    inet_pton(AF_INET6, "2040::", &addr2);
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 10, &addr2));

    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7333", &addr2);
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 127, &addr2));
    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7335", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 127, &addr2));
    inet_pton(AF_INET6, "2001:0db8:85a3:0000:0000:8a2e:0370:7336", &addr2);
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 127, &addr2));

    inet_pton(AF_INET6, "0000:0000:0000:0000:0000:0000:0000:0000", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 1, &addr2));
    inet_pton(AF_INET6, "7fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr2);
    ASSERT_TRUE(ipv6_addr_within_subnet(&addr1, 1, &addr2));
    inet_pton(AF_INET6, "8000:0000:0000:0000:0000:0000:0000:0000", &addr2);
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 1, &addr2));
    inet_pton(AF_INET6, "8fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", &addr2);
    ASSERT_FALSE(ipv6_addr_within_subnet(&addr1, 1, &addr2));
}