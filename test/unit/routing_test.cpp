// Source-address selection on connect(2). When a SUT connects to a remote,
// the model must pick a local address whose subnet covers the remote (or
// fall back to the default-gateway interface). This is what
// generate_local_addr / routing_table_lookup do behind the scenes, and getsockname
// is the observable.
//
// nfl-only: native source selection depends on the live host's routing table,
// which varies per machine.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <string>

extern "C" {
int nfl_add_l2_iface(const char *name, short flags, int mtu,
                     const char *hw_addr, const char *hw_broadcast_addr,
                     unsigned int *device_index);
int nfl_add_l3_iface_ipv4(unsigned int device_index, const char *addr_text,
                          const char *netmask_text);
int nfl_set_ipv4_default_gateway(const char *gateway_addr_text,
                                 unsigned int device_index);
}

#if defined(NFL_TEST_NATIVE_MODE)
// tests_native isn't linked against netfuzzlib. Every test in this file is
// SKIP_IF_NATIVE, so these stubs are never reached at runtime. They exist
// only to satisfy the linker.
extern "C" {
int nfl_add_l2_iface(const char *, short, int, const char *, const char *, unsigned int *) {
    return -1;
}
int nfl_add_l3_iface_ipv4(unsigned int, const char *, const char *) { return -1; }
int nfl_set_ipv4_default_gateway(const char *, unsigned int) { return -1; }
}
#endif

using namespace nfl_test;

namespace {

// Add an extra interface with a specific subnet to the running model.
// Per-test process isolation (gtest_discover_tests) means this only affects
// the current test.
unsigned int add_iface(const char *name, const char *addr, const char *mask) {
    // 0xff narrows to signed char in C++ (`-Wc++11-narrowing` errors), so store
    // as unsigned and reinterpret_cast at the API boundary.
    static const unsigned char mac[6] = {0x02, 0, 0, 0, 0, 0x42};
    static const unsigned char brd[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    unsigned int idx = 0;
    if (nfl_add_l2_iface(name, IFF_BROADCAST | IFF_MULTICAST | IFF_UP | IFF_RUNNING,
                         1500, reinterpret_cast<const char *>(mac),
                         reinterpret_cast<const char *>(brd), &idx) != 0) {
        return 0;
    }
    if (nfl_add_l3_iface_ipv4(idx, addr, mask) != 0) {
        return 0;
    }
    return idx;
}

// Given a remote IP, connect a UDP socket and read back the kernel-assigned
// source via getsockname.
std::string connect_then_get_source(const char *remote) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return "<socket-fail>";
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    inet_pton(AF_INET, remote, &dst.sin_addr);
    if (connect(fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)) != 0) {
        close(fd);
        return "<connect-fail>";
    }
    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(fd, reinterpret_cast<sockaddr *>(&bound), &len) != 0) {
        close(fd);
        return "<getsockname-fail>";
    }
    char buf[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &bound.sin_addr, buf, sizeof(buf));
    close(fd);
    return buf;
}

}  // namespace

class RoutingTest : public NetIOTest {};

TEST_F(RoutingTest, ConnectToLoopbackPicksLoopback) {
    SKIP_IF_NATIVE();
    EXPECT_EQ(connect_then_get_source("127.0.0.5"), "127.0.0.1");
}

TEST_F(RoutingTest, ConnectInDirectlyConnectedSubnetPicksThatIface) {
    SKIP_IF_NATIVE();
    ASSERT_NE(0u, add_iface("ext0", "10.0.0.5", "255.255.255.0"));
    EXPECT_EQ(connect_then_get_source("10.0.0.99"), "10.0.0.5");
}

TEST_F(RoutingTest, ConnectToRemoteFollowsDefaultGateway) {
    // No directly-connected route covers 8.8.8.8, so the kernel picks the
    // interface that owns the default gateway. We configure ext0 with
    // 10.0.0.5/24 and a 10.0.0.1 gateway, and connect(8.8.8.8) must return
    // 10.0.0.5 as the source.
    SKIP_IF_NATIVE();
    unsigned int idx = add_iface("ext0", "10.0.0.5", "255.255.255.0");
    ASSERT_NE(0u, idx);
    ASSERT_EQ(0, nfl_set_ipv4_default_gateway("10.0.0.1", idx));
    EXPECT_EQ(connect_then_get_source("8.8.8.8"), "10.0.0.5");
}

TEST_F(RoutingTest, ConnectWithNoRouteFailsENETUNREACH) {
    // Without any default gateway and a remote outside every configured
    // subnet, connect must surface ENETUNREACH. (The default test module
    // configures only eth0=192.0.2.1/24 + lo, no gateway.)
    SKIP_IF_NATIVE();
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    inet_pton(AF_INET, "8.8.8.8", &dst.sin_addr);
    EXPECT_LIBC_FAIL(connect(fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)),
                     ENETUNREACH);
    close(fd);
}
