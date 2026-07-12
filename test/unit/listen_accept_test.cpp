// listen(2) / accept(2) / accept4(2): argument validation, the SOCK_NONBLOCK
// flag propagation, EAGAIN with no pending connection.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

class ListenAcceptTest : public NetIOTest {};

TEST_F(ListenAcceptTest, ListenOnBoundTcpSocketSucceeds) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    EXPECT_EQ(0, listen(s, 5));
    close(s);
}

TEST_F(ListenAcceptTest, ListenSetsSoAcceptconn) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));
    int v = -1;
    socklen_t len = sizeof(v);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &v, &len));
    EXPECT_NE(v, 0);
    close(s);
}

TEST_F(ListenAcceptTest, ListenOnUdpReturnsEopnotsupp) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LIBC_FAIL(listen(s, 5), EOPNOTSUPP);
    close(s);
}

TEST_F(ListenAcceptTest, ListenOnUnboundSocketAutoBinds) {
    // Linux: listen() on a TCP socket with no prior bind auto-assigns a
    // wildcard address with an ephemeral port.
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, listen(s, 5));

    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&bound), &len));
    EXPECT_NE(bound.sin_port, 0);
    close(s);
}

TEST_F(ListenAcceptTest, AcceptOnNonStreamReturnsEopnotsupp) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    EXPECT_LIBC_FAIL(accept(s, reinterpret_cast<sockaddr *>(&peer), &len),
                     EOPNOTSUPP);
    close(s);
}

TEST_F(ListenAcceptTest, AcceptOnNonListeningTcpReturnsEinval) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    EXPECT_LIBC_FAIL(accept(s, reinterpret_cast<sockaddr *>(&peer), &len),
                     EINVAL);
    close(s);
}

TEST_F(ListenAcceptTest, NonblockingAcceptWithNoPendingReturnsEagain) {
    const int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));

    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    EXPECT_LIBC_FAIL(accept(s, reinterpret_cast<sockaddr *>(&peer), &len),
                     EAGAIN);
    close(s);
}

TEST_F(ListenAcceptTest, Accept4SockNonblockSetsFlagOnNewFd) {
    // accept4(SOCK_NONBLOCK) must set O_NONBLOCK on the *new* fd, not the
    // listening one. Native: harder to set up without a real connect, so we
    // use the test module's pending-accept hook in nfl mode.
    SKIP_IF_NATIVE();
    module_test_set_pending_tcp_accepts(1);

    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));

    sockaddr_in peer{};
    socklen_t len = sizeof(peer);
    const int new_fd = accept4(s, reinterpret_cast<sockaddr *>(&peer), &len, SOCK_NONBLOCK);
    ASSERT_GE(new_fd, 0);

    // The listening socket must remain in its original (blocking) state.
    int listen_fl = fcntl(s, F_GETFL);
    ASSERT_GE(listen_fl, 0);
    EXPECT_FALSE(listen_fl & O_NONBLOCK);

    // The new fd must be non-blocking.
    int new_fl = fcntl(new_fd, F_GETFL);
    ASSERT_GE(new_fl, 0);
    EXPECT_TRUE(new_fl & O_NONBLOCK);

    close(new_fd);
    close(s);
}

TEST_F(ListenAcceptTest, ListenIsIdempotent) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    EXPECT_EQ(0, listen(s, 5));
    EXPECT_EQ(0, listen(s, 10));  // calling again with new backlog OK
    close(s);
}

TEST_F(ListenAcceptTest, AcceptWithNullAddrSucceeds) {
    // accept(2): both addr and addrlen may be NULL when the caller doesn't
    // care about the peer address. Use the test-module hook to make accept
    // succeed in nfl mode. Native skips because we'd need a real connect.
    SKIP_IF_NATIVE();
    module_test_set_pending_tcp_accepts(1);

    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));

    const int new_fd = accept(s, nullptr, nullptr);
    ASSERT_GE(new_fd, 0);
    close(new_fd);
    close(s);
}

TEST_F(ListenAcceptTest, PollListenerHasPollinIffPendingConnections) {
    // POLLIN on a listening TCP socket reflects "accept(2) would not block".
    // No pending → no POLLIN. Two pending → POLLIN. After consuming both
    // via accept() → no POLLIN again. Native: hard to set up reliably
    // without a real client, so nfl drives pending count via the test module.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));

    auto poll_in = [&]() {
        pollfd p{s, POLLIN, 0};
        EXPECT_GE(poll(&p, 1, 0), 0);
        return (p.revents & POLLIN) != 0;
    };

    EXPECT_FALSE(poll_in()) << "no pending connections → no POLLIN";

    module_test_set_pending_tcp_accepts(2);
    EXPECT_TRUE(poll_in()) << "two pending → POLLIN";

    int c1 = accept(s, nullptr, nullptr);
    ASSERT_GE(c1, 0);
    EXPECT_TRUE(poll_in()) << "one still pending after first accept";

    int c2 = accept(s, nullptr, nullptr);
    ASSERT_GE(c2, 0);
    EXPECT_FALSE(poll_in()) << "queue drained → no POLLIN";

    close(c1);
    close(c2);
    close(s);
}