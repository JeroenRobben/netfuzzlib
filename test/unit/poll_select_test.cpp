// poll(2) / select(2): readability/writability after data, POLLOUT for unconnected
// UDP, POLLNVAL for invalid fds.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

class PollSelectTest : public NetIOTest {};

TEST_F(PollSelectTest, FreshUdpSocketIsWritable) {
    // POLLOUT must be set on a UDP socket regardless of whether it's
    // connected, datagrams have no notion of "connection".
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));

    pollfd p{s, POLLOUT, 0};
    EXPECT_EQ(1, poll(&p, 1, 0));
    EXPECT_TRUE(p.revents & POLLOUT);
    close(s);
}

TEST_F(PollSelectTest, EmptyUdpSocketHasNoPollin) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));

    pollfd p{s, POLLIN, 0};
    EXPECT_EQ(0, poll(&p, 1, 0));
    EXPECT_FALSE(p.revents & POLLIN);
    close(s);
}

TEST_F(PollSelectTest, PollinSetAfterIncomingDatagram) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "x";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    pollfd p{recv_sock.fd, POLLIN, 0};
    EXPECT_EQ(1, poll(&p, 1, 0));
    EXPECT_TRUE(p.revents & POLLIN);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(PollSelectTest, SelectReadAfterIncomingDatagram) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "x";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(recv_sock.fd, &rfds);
    timeval tv{0, 0};
    EXPECT_EQ(1, select(recv_sock.fd + 1, &rfds, nullptr, nullptr, &tv));
    EXPECT_TRUE(FD_ISSET(recv_sock.fd, &rfds));

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(PollSelectTest, PollnvalForInvalidFd) {
    // Use an fd we know is closed.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    close(s);

    pollfd p{s, POLLIN, 0};
    EXPECT_EQ(1, poll(&p, 1, 0));
    EXPECT_TRUE(p.revents & POLLNVAL);
}

TEST_F(PollSelectTest, PollWithEmptyFdsAndZeroTimeoutReturnsZero) {
    EXPECT_EQ(0, poll(nullptr, 0, 0));
}

TEST_F(PollSelectTest, SelectWithNoFdsAndZeroTimeoutReturnsZero) {
    timeval tv{0, 0};
    EXPECT_EQ(0, select(0, nullptr, nullptr, nullptr, &tv));
}

TEST_F(PollSelectTest, PollMultipleFdsReportsCorrectRevents) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto idle_sock = make_bound_udp_v4();
    ASSERT_GE(idle_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = ".";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    pollfd pfds[2];
    pfds[0] = {recv_sock.fd, POLLIN, 0};
    pfds[1] = {idle_sock.fd, POLLIN, 0};
    const int n = poll(pfds, 2, 0);
    EXPECT_EQ(n, 1);
    EXPECT_TRUE(pfds[0].revents & POLLIN);
    EXPECT_FALSE(pfds[1].revents & POLLIN);

    close(send_sock.fd);
    close(idle_sock.fd);
    close(recv_sock.fd);
}
