// shutdown(2): argument validation, behavior on UDP send/recv after shutdown.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

class ShutdownTest : public NetIOTest {};

TEST_F(ShutdownTest, InvalidHowReturnsEinval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    EXPECT_LIBC_FAIL(shutdown(s, 9999), EINVAL);
    close(s);
}

TEST_F(ShutdownTest, ShutdownOnUnconnectedTcpReturnsEnotconn) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LIBC_FAIL(shutdown(s, SHUT_RDWR), ENOTCONN);
    close(s);
}

TEST_F(ShutdownTest, ShutdownReadOnConnectedUdpThenRecvReturnsZero) {
    // After shutdown(SHUT_RD) recv must return 0 (end-of-stream), not -1.
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    sockaddr_in peer = loopback_v4(send_sock.port);
    ASSERT_EQ(0, connect(recv_sock.fd, reinterpret_cast<sockaddr *>(&peer),
                         sizeof(peer)));
    ASSERT_EQ(0, shutdown(recv_sock.fd, SHUT_RD));

    char buf[16];
    ssize_t got = recv(recv_sock.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, 0);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(ShutdownTest, ShutdownWriteOnConnectedUdpThenSendReturnsEpipe) {
    auto a = make_bound_udp_v4();
    ASSERT_GE(a.fd, 0);
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));
    ASSERT_EQ(0, shutdown(a.fd, SHUT_WR));

    const char msg[] = "after-shutdown";
    EXPECT_LIBC_FAIL(send(a.fd, msg, sizeof(msg), MSG_NOSIGNAL), EPIPE);

    close(a.fd);
    close(b.fd);
}

TEST_F(ShutdownTest, ShutdownRdwrOnConnectedUdp) {
    auto a = make_bound_udp_v4();
    ASSERT_GE(a.fd, 0);
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));
    EXPECT_EQ(0, shutdown(a.fd, SHUT_RDWR));

    close(a.fd);
    close(b.fd);
}

TEST_F(ShutdownTest, MultipleShutdownsAreIdempotent) {
    auto a = make_bound_udp_v4();
    ASSERT_GE(a.fd, 0);
    auto b = make_bound_udp_v4();
    ASSERT_GE(b.fd, 0);

    sockaddr_in peer = loopback_v4(b.port);
    ASSERT_EQ(0, connect(a.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));
    EXPECT_EQ(0, shutdown(a.fd, SHUT_RD));
    EXPECT_EQ(0, shutdown(a.fd, SHUT_RD));   // idempotent
    EXPECT_EQ(0, shutdown(a.fd, SHUT_RDWR)); // upgrade to RDWR allowed

    close(a.fd);
    close(b.fd);
}
