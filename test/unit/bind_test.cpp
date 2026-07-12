// Tests for bind(2): argument validation, addrlen tolerance (oversize OK),
// family mismatch errno, double-bind.

#include "test_helpers.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

using namespace nfl_test;

TEST(BindTest, LoopbackEphemeralPortSucceeds) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = loopback_v4(0);
    EXPECT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));
    close(s);
}

TEST(BindTest, GetSocknameAfterBindReturnsBoundAddr) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = loopback_v4(0);
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&bound), &len));
    EXPECT_EQ(len, sizeof(sockaddr_in));
    EXPECT_EQ(bound.sin_family, AF_INET);
    EXPECT_EQ(bound.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    EXPECT_NE(bound.sin_port, 0);  // OS assigned an ephemeral port
    close(s);
}

TEST(BindTest, OversizeAddrlenIsAccepted) {
    // POSIX requires addrlen >= sizeof(sockaddr_in). Larger is fine. The model
    // used to reject anything not exactly equal, so verify both the kernel and
    // the model accept sockaddr_storage-sized buffers.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_storage ss{};
    auto *sa = reinterpret_cast<sockaddr_in *>(&ss);
    *sa = loopback_v4(0);
    EXPECT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&ss), sizeof(ss)));
    close(s);
}

TEST(BindTest, TooShortAddrlenRejected) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = loopback_v4(0);
    EXPECT_LIBC_FAIL(bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa) - 4),
                     EINVAL);
    close(s);
}

TEST(BindTest, FamilyMismatchReturnsEafnosupport) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in6 sa = loopback_v6(0);  // wrong family for AF_INET socket
    EXPECT_LIBC_FAIL(bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)),
                     EAFNOSUPPORT);
    close(s);
}

TEST(BindTest, DoubleBindRejected) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = loopback_v4(0);
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));
    EXPECT_LIBC_FAIL(bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)),
                     EINVAL);
    close(s);
}

TEST(BindTest, BindV6SocketSucceeds) {
    const int s = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in6 sa = loopback_v6(0);
    EXPECT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));
    close(s);
}

TEST(BindTest, BindV6SocketToV4MappedLoopbackSucceeds) {
    // Java's NIO and other dual-stack runtimes bind v4 addresses through
    // an AF_INET6 socket as ::ffff:<v4>. The kernel accepts it natively, and
    // can_bind_ipv6_addr now unwraps the v4-mapped prefix and defers to
    // the v4 bind check.
    const int s = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = 0;
    // ::ffff:127.0.0.1
    sa.sin6_addr.s6_addr[10] = 0xff;
    sa.sin6_addr.s6_addr[11] = 0xff;
    sa.sin6_addr.s6_addr[12] = 127;
    sa.sin6_addr.s6_addr[15] = 1;
    EXPECT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));
    close(s);
}

TEST(BindTest, BindV6SocketToV4MappedNonInterfaceFails) {
    // v4-mapped of a non-configured v4 address must reject like the v4
    // bind would, the same EADDRNOTAVAIL the kernel gives.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    // ::ffff:203.0.113.55  (RFC 5737 TEST-NET-3, never on a local iface)
    sa.sin6_addr.s6_addr[10] = 0xff;
    sa.sin6_addr.s6_addr[11] = 0xff;
    sa.sin6_addr.s6_addr[12] = 203;
    sa.sin6_addr.s6_addr[13] = 0;
    sa.sin6_addr.s6_addr[14] = 113;
    sa.sin6_addr.s6_addr[15] = 55;
    EXPECT_LIBC_FAIL(bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)),
                     EADDRNOTAVAIL);
    close(s);
}

TEST(BindTest, BindToWildcardAddressSucceeds) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = 0;
    EXPECT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    // After wildcard bind, getsockname returns wildcard + the assigned port.
    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&bound), &len));
    EXPECT_EQ(bound.sin_addr.s_addr, htonl(INADDR_ANY));
    EXPECT_NE(bound.sin_port, 0);
    close(s);
}

TEST(BindTest, BindToInaccessibleAddrFails) {
    // Binding to an address not configured on any local interface fails with
    // EADDRNOTAVAIL (Linux semantics).
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = inet_addr_v4("203.0.113.55", 0);  // RFC 5737 TEST-NET-3
    EXPECT_LIBC_FAIL(bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)),
                     EADDRNOTAVAIL);
    close(s);
}

TEST(BindTest, BindPreservesSpecifiedPort) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    // Pick a high port unlikely to be in use. 0 means kernel picks one.
    sockaddr_in sa = loopback_v4(0);
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));
    sockaddr_in first_bound{};
    socklen_t len = sizeof(first_bound);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&first_bound), &len));
    const uint16_t kernel_port = ntohs(first_bound.sin_port);
    ASSERT_NE(kernel_port, 0);

    close(s);

    // Now create a fresh socket and bind it to that exact port, a round-trip check.
    const int s2 = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s2, 0);
    sockaddr_in target = loopback_v4(kernel_port);
    EXPECT_EQ(0, bind(s2, reinterpret_cast<sockaddr *>(&target), sizeof(target)));
    sockaddr_in second_bound{};
    len = sizeof(second_bound);
    ASSERT_EQ(0, getsockname(s2, reinterpret_cast<sockaddr *>(&second_bound), &len));
    EXPECT_EQ(ntohs(second_bound.sin_port), kernel_port);
    close(s2);
}
