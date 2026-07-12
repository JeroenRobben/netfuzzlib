// connect(2): UDP default-destination, AF_UNSPEC clears, family validation,
// addrlen tolerance.

#include "test_helpers.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

using namespace nfl_test;

class ConnectTest : public NetIOTest {};

TEST_F(ConnectTest, ConnectUdpThenGetpeernameReportsRemote) {
    auto a = make_bound_udp_v4();
    ASSERT_GE(a.fd, 0);
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));

    sockaddr_in got{};
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getpeername(a.fd, reinterpret_cast<sockaddr *>(&got), &len));
    EXPECT_EQ(got.sin_family, AF_INET);
    EXPECT_EQ(ntohs(got.sin_port), b.port);
    EXPECT_EQ(got.sin_addr.s_addr, htonl(INADDR_LOOPBACK));

    close(a.fd);
    close(b.fd);
}

TEST_F(ConnectTest, AfUnspecOnUdpClearsRemote) {
    auto a = make_bound_udp_v4();
    ASSERT_GE(a.fd, 0);
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));

    sockaddr_storage clear{};
    clear.ss_family = AF_UNSPEC;
    EXPECT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&clear), sizeof(clear)));

    sockaddr_in got{};
    socklen_t len = sizeof(got);
    EXPECT_LIBC_FAIL(getpeername(a.fd, reinterpret_cast<sockaddr *>(&got), &len),
                     ENOTCONN);

    close(a.fd);
    close(b.fd);
}

TEST_F(ConnectTest, FamilyMismatchReturnsEafnosupport) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in6 peer = loopback_v6(1234);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)),
                     EAFNOSUPPORT);
    close(s);
}

TEST_F(ConnectTest, AddrlenTooSmallReturnsEinval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in peer = loopback_v4(1234);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&peer), sizeof(peer) - 4),
                     EINVAL);
    close(s);
}

TEST_F(ConnectTest, OversizeAddrlenAccepted) {
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    const int a = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(a, 0);
    sockaddr_storage ss{};
    auto *peer = reinterpret_cast<sockaddr_in *>(&ss);
    *peer = loopback_v4(b.port);
    EXPECT_EQ(0, connect(a, reinterpret_cast<sockaddr *>(&ss), sizeof(ss)));

    close(a);
    close(b.fd);
}

TEST_F(ConnectTest, ConnectThenSendDeliversToPeer) {
    // End-to-end: connect on sender, recv on listener via the loopback queue.
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    const int send_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(send_fd, 0);

    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(0, connect(send_fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    const char msg[] = "via-connect";
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              send(send_fd, msg, sizeof(msg), 0));

    char buf[64] = {};
    EXPECT_EQ(static_cast<ssize_t>(sizeof(msg)),
              recv(recv_sock.fd, buf, sizeof(buf), 0));
    EXPECT_STREQ(buf, msg);

    close(send_fd);
    close(recv_sock.fd);
}

TEST_F(ConnectTest, GetpeernameOnUnconnectedReturnsEnotconn) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in addr{};
    socklen_t len = sizeof(addr);
    EXPECT_LIBC_FAIL(getpeername(s, reinterpret_cast<sockaddr *>(&addr), &len),
                     ENOTCONN);
    close(s);
}

TEST_F(ConnectTest, ConnectAddrIsCopiedNotAliased) {
    // Mutating the caller's sockaddr_in after connect must not affect the
    // socket's stored peer address.
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);
    const int a = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(a, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));

    // Stomp on the local copy.
    peer.sin_port = htons(0xdead);
    peer.sin_addr.s_addr = htonl(0x01020304);

    sockaddr_in got{};
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getpeername(a, reinterpret_cast<sockaddr *>(&got), &len));
    EXPECT_EQ(ntohs(got.sin_port), b.port);
    EXPECT_EQ(got.sin_addr.s_addr, htonl(INADDR_LOOPBACK));

    close(a);
    close(b.fd);
}
