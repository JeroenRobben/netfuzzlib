// Direct unit tests for the utility helpers in src/core/addr.h.
// These are pure functions but pulled in to libnfl only, so they have no
// equivalent in libc, so every case is nfl-only. Native-mode link stubs at
// the bottom satisfy the linker for tests_native (which doesn't link the
// model).

#include "test_helpers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstdint>
#include <cstring>

extern "C" {
// nfl_addr_t is a union of struct sockaddr / sockaddr_in / sockaddr_in6 / sockaddr_nl
// (defined in include/netfuzzlib/types.h). At the ABI level a pointer to
// nfl_addr_t is interchangeable with a pointer to any of those, since the union
// starts with `struct sockaddr s` at offset 0.
bool addr_is_zero_address(const void *addr);
bool ip_endpoints_match(const void *addr1, const void *addr2);
uint16_t nfl_addr_get_port_network_byte_order(const void *addr);
}

#if defined(NFL_TEST_NATIVE_MODE)
extern "C" {
bool addr_is_zero_address(const void *) { return false; }
bool ip_endpoints_match(const void *, const void *) { return false; }
uint16_t nfl_addr_get_port_network_byte_order(const void *) { return 0; }
}
#endif

using namespace nfl_test;

namespace {

sockaddr_in v4(const char *addr, uint16_t port) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, addr, &sa.sin_addr);
    return sa;
}

sockaddr_in6 v6(const char *addr, uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    inet_pton(AF_INET6, addr, &sa.sin6_addr);
    return sa;
}

}  // namespace

class UtilTest : public ::testing::Test {};

// ---- addr_is_zero_address --------------------------------------------------

TEST_F(UtilTest, AddrIsZeroAddressIpv4Wildcard) {
    SKIP_IF_NATIVE();
    sockaddr_in sa = v4("0.0.0.0", 0);
    EXPECT_TRUE(addr_is_zero_address(&sa));
}

TEST_F(UtilTest, AddrIsZeroAddressIpv4NonZero) {
    SKIP_IF_NATIVE();
    sockaddr_in sa = v4("127.0.0.1", 0);
    EXPECT_FALSE(addr_is_zero_address(&sa));
}

TEST_F(UtilTest, AddrIsZeroAddressIpv6Unspec) {
    SKIP_IF_NATIVE();
    sockaddr_in6 sa = v6("::", 0);
    EXPECT_TRUE(addr_is_zero_address(&sa));
}

TEST_F(UtilTest, AddrIsZeroAddressIpv6NonZero) {
    SKIP_IF_NATIVE();
    sockaddr_in6 sa = v6("::1", 0);
    EXPECT_FALSE(addr_is_zero_address(&sa));
}

// ---- ip_endpoints_match ----------------------------------------------------

TEST_F(UtilTest, IpEndpointsMatchIdenticalIpv4) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("127.0.0.1", 80);
    sockaddr_in b = v4("127.0.0.1", 80);
    EXPECT_TRUE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchDifferentAddrIpv4) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("127.0.0.1", 80);
    sockaddr_in b = v4("127.0.0.2", 80);
    EXPECT_FALSE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchDifferentPortIpv4) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("127.0.0.1", 80);
    sockaddr_in b = v4("127.0.0.1", 81);
    EXPECT_FALSE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchOneZeroPortIsWildcard) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("127.0.0.1", 80);
    sockaddr_in b = v4("127.0.0.1", 0);
    EXPECT_TRUE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchWildcardAddrIpv4) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("0.0.0.0", 80);
    sockaddr_in b = v4("127.0.0.1", 80);
    EXPECT_TRUE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchDifferentFamilyMismatch) {
    SKIP_IF_NATIVE();
    sockaddr_in a = v4("127.0.0.1", 80);
    sockaddr_in6 b = v6("::1", 80);
    EXPECT_FALSE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchIdenticalIpv6) {
    SKIP_IF_NATIVE();
    sockaddr_in6 a = v6("2001:db8::1", 80);
    sockaddr_in6 b = v6("2001:db8::1", 80);
    EXPECT_TRUE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchDifferentAddrIpv6) {
    SKIP_IF_NATIVE();
    sockaddr_in6 a = v6("2001:db8::1", 80);
    sockaddr_in6 b = v6("2001:db8::2", 80);
    EXPECT_FALSE(ip_endpoints_match(&a, &b));
}

TEST_F(UtilTest, IpEndpointsMatchWildcardAddrIpv6) {
    SKIP_IF_NATIVE();
    sockaddr_in6 a = v6("::", 80);
    sockaddr_in6 b = v6("2001:db8::1", 80);
    EXPECT_TRUE(ip_endpoints_match(&a, &b));
}

// ---- nfl_addr_get_port_network_byte_order ----------------------------------

TEST_F(UtilTest, NflAddrGetPortIpv4) {
    SKIP_IF_NATIVE();
    sockaddr_in sa = v4("127.0.0.1", 8080);
    EXPECT_EQ(htons(8080), nfl_addr_get_port_network_byte_order(&sa));
}

TEST_F(UtilTest, NflAddrGetPortIpv6) {
    SKIP_IF_NATIVE();
    sockaddr_in6 sa = v6("::1", 9090);
    EXPECT_EQ(htons(9090), nfl_addr_get_port_network_byte_order(&sa));
}
