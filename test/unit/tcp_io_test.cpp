// TCP stream-socket I/O covering connect, listen, accept, send, recv, shutdown
// paths in src/core/stream.c that the integration tests cover only
// transitively. Most cases are nfl-only because the default test module's
// nfl_tcp_connect refuses outbound connect. Tests that need a "connected" fd
// drive it via listen + module_test_set_pending_tcp_accepts(1) + accept and
// then push bytes through the test module's loopback queue with a UDP socket.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <cstring>

using namespace nfl_test;

namespace {

// Set up a TCP listener on 127.0.0.1, queue one pending accept in the test
// module, and return {accepted_fd, listener_fd, listener_port}. Caller closes
// both fds. SKIP_IF_NATIVE before calling, since accept blocks on the kernel
// without a real client.
struct ConnectedTcp {
    int conn;
    int srv;
    uint16_t srv_port;
};
ConnectedTcp accept_one_loopback() {
    module_test_set_pending_tcp_accepts(1);
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_GE(srv, 0);
    const uint16_t port = bind_loopback_v4_ephemeral(srv);
    EXPECT_NE(0u, port);
    EXPECT_EQ(0, listen(srv, 5));
    int conn = accept(srv, nullptr, nullptr);
    EXPECT_GE(conn, 0);
    return {conn, srv, port};
}

// As accept_one_loopback(), but with the accepted fd switched to non-blocking,
// so recv/poll/select on it exercise the inter-packet gap.
ConnectedTcp accept_one_loopback_nonblocking() {
    ConnectedTcp t = accept_one_loopback();
    const int fl = fcntl(t.conn, F_GETFL);
    EXPECT_GE(fl, 0);
    EXPECT_EQ(0, fcntl(t.conn, F_SETFL, fl | O_NONBLOCK));
    return t;
}

// Push `len` bytes destined for 127.0.0.1:port into the loopback queue via a
// throwaway UDP socket. The test module's filter is destination-only, so a
// TCP recv on a fd bound to that addr will pick the packet up.
void inject_to_loopback_port(uint16_t port, const void *data, size_t len) {
    int u = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(u, 0);
    sockaddr_in dst = loopback_v4(port);
    ASSERT_EQ(static_cast<ssize_t>(len),
              sendto(u, data, len, 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    close(u);
}

volatile sig_atomic_t g_sigpipe_count = 0;
void count_sigpipe(int) { g_sigpipe_count++; }

}  // namespace

class TcpIoTest : public NetIOTest {};

// ---- connect ---------------------------------------------------------------

TEST_F(TcpIoTest, ConnectTcpRefusedByModuleReturnsEconnrefused) {
    SKIP_IF_NATIVE();  // default test module's nfl_tcp_connect returns false
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in dst = inet_addr_v4("192.0.2.99", 12345);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)),
                     ECONNREFUSED);
    close(s);
}

TEST_F(TcpIoTest, ConnectTcpUnroutableReturnsEnetunreach) {
    SKIP_IF_NATIVE();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in dst = inet_addr_v4("8.8.8.8", 12345);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)),
                     ENETUNREACH);
    close(s);
}

TEST_F(TcpIoTest, ConnectAfUnspecOnUnconnectedTcpIsNoop) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in clear{};
    clear.sin_family = AF_UNSPEC;
    EXPECT_EQ(0, connect(s, reinterpret_cast<sockaddr *>(&clear), sizeof(clear)));
    close(s);
}

TEST_F(TcpIoTest, ConnectOnListeningTcpReturnsEisconn) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    ASSERT_EQ(0, listen(s, 5));
    sockaddr_in dst = inet_addr_v4("192.0.2.99", 12345);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)),
                     EISCONN);
    close(s);
}

TEST_F(TcpIoTest, ConnectShortAddrlenReturnsEinval) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in dst = inet_addr_v4("192.0.2.99", 12345);
    EXPECT_LIBC_FAIL(connect(s, reinterpret_cast<sockaddr *>(&dst), sizeof(dst) - 4),
                     EINVAL);
    close(s);
}

// ---- listen edge cases -----------------------------------------------------

TEST_F(TcpIoTest, ListenOnConnectedTcpReturnsEinval) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    // accepted fd is already "connected", so listen() must reject.
    EXPECT_LIBC_FAIL(listen(t.conn, 5), EINVAL);
    close(t.conn);
    close(t.srv);
}

// ---- recv / send on unconnected -------------------------------------------

TEST_F(TcpIoTest, RecvOnUnconnectedStreamReturnsEnotconn) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    char buf[1];
    EXPECT_LIBC_FAIL(recv(s, buf, sizeof(buf), 0), ENOTCONN);
    close(s);
}

TEST_F(TcpIoTest, SendOnUnconnectedStreamReturnsEnotconn) {
    // Model returns ENOTCONN. Linux returns EPIPE (and SIGPIPE w/o
    // MSG_NOSIGNAL). Aligning the model would require modeling SIGPIPE,
    // which is outside this change's scope, so kept nfl-only for now.
    SKIP_IF_NATIVE();
    int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    const char data[] = "x";
    EXPECT_LIBC_FAIL(send(s, data, 1, 0), ENOTCONN);
    close(s);
}

// ---- send/recv on accepted fd ---------------------------------------------

TEST_F(TcpIoTest, SendtoOnConnectedTcpWithExplicitAddrReturnsEisconn) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const char data[] = "x";
    sockaddr_in dst = loopback_v4(t.srv_port);
    EXPECT_LIBC_FAIL(sendto(t.conn, data, 1, 0,
                            reinterpret_cast<sockaddr *>(&dst), sizeof(dst)),
                     EISCONN);
    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, SendOnAcceptedTcpEnqueuesPayload) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const char msg[] = "hello";
    EXPECT_EQ(static_cast<ssize_t>(sizeof(msg) - 1),
              send(t.conn, msg, sizeof(msg) - 1, 0));
    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, RecvOnAcceptedTcpDeliversInjectedBytes) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const char payload[] = "hello";
    inject_to_loopback_port(t.srv_port, payload, sizeof(payload) - 1);

    char buf[16] = {};
    const ssize_t n = recv(t.conn, buf, sizeof(buf), 0);
    EXPECT_EQ(static_cast<ssize_t>(sizeof(payload) - 1), n);
    EXPECT_EQ(0, memcmp(buf, payload, sizeof(payload) - 1));

    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, RecvAfterShutdownRdReturnsZero) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    ASSERT_EQ(0, shutdown(t.conn, SHUT_RD));
    char buf[1];
    EXPECT_EQ(0, recv(t.conn, buf, sizeof(buf), 0));  // EOF, no errno
    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, NonblockingRecvOnEmptyAcceptedFdReturnsEagain) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    // accept_one_loopback's listener is blocking, so the accepted fd inherits
    // the listener's blocking state. Flip explicitly with fcntl.
    const int fl = fcntl(t.conn, F_GETFL);
    ASSERT_GE(fl, 0);
    ASSERT_EQ(0, fcntl(t.conn, F_SETFL, fl | O_NONBLOCK));
    char buf[1];
    EXPECT_LIBC_FAIL(recv(t.conn, buf, sizeof(buf), 0), EAGAIN);
    close(t.conn);
    close(t.srv);
}

// A non-blocking stream recv reports one EAGAIN "gap" at each packet boundary,
// so distinct module packets are never delivered back-to-back. This forces the
// SUT's read loop to re-poll between packets. Blocking sockets are exempt.
TEST_F(TcpIoTest, NonblockingStreamInsertsEagainGapBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const int fl = fcntl(t.conn, F_GETFL);
    ASSERT_GE(fl, 0);
    ASSERT_EQ(0, fcntl(t.conn, F_SETFL, fl | O_NONBLOCK));

    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "AAA", 3));
    EXPECT_LIBC_FAIL(recv(t.conn, buf, sizeof(buf), 0), EAGAIN);  // enforced gap
    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

// The gap is armed only when a packet is fully consumed, never mid-packet:
// partial reads of one packet must flow without an intervening EAGAIN.
TEST_F(TcpIoTest, NonblockingStreamGapIsPerPacketBoundaryNotPerRead) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const int fl = fcntl(t.conn, F_GETFL);
    ASSERT_GE(fl, 0);
    ASSERT_EQ(0, fcntl(t.conn, F_SETFL, fl | O_NONBLOCK));

    inject_to_loopback_port(t.srv_port, "HELLO", 5);
    inject_to_loopback_port(t.srv_port, "XY", 2);

    char buf[2] = {};
    EXPECT_EQ(2, recv(t.conn, buf, sizeof(buf), 0));  // "HE" (mid-packet)
    EXPECT_EQ(0, memcmp(buf, "HE", 2));
    EXPECT_EQ(2, recv(t.conn, buf, sizeof(buf), 0));  // "LL", no mid-packet gap
    EXPECT_EQ(0, memcmp(buf, "LL", 2));
    EXPECT_EQ(1, recv(t.conn, buf, sizeof(buf), 0));  // "O", packet boundary
    EXPECT_EQ(0, memcmp(buf, "O", 1));
    EXPECT_LIBC_FAIL(recv(t.conn, buf, sizeof(buf), 0), EAGAIN);  // gap before next
    EXPECT_EQ(2, recv(t.conn, buf, sizeof(buf), 0));  // "XY"
    EXPECT_EQ(0, memcmp(buf, "XY", 2));

    close(t.conn);
    close(t.srv);
}

// Blocking stream recv is exempt: packets arrive back-to-back with no gap.
// (Stops after two reads. A third blocking recv on an empty queue would idle.)
TEST_F(TcpIoTest, BlockingStreamDeliversPacketsWithoutGap) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();  // accepted fd inherits the blocking listener
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "AAA", 3));
    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));  // no gap for blocking
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, RecvMsgTruncDiscardsBytesAndReturnsCount) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const char payload[] = "abcdefgh";  // 8 bytes
    inject_to_loopback_port(t.srv_port, payload, sizeof(payload) - 1);

    // Discard 3 bytes via MSG_TRUNC.
    char trash[3];
    iovec iov{trash, sizeof(trash)};
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    EXPECT_EQ(3, recvmsg(t.conn, &m, MSG_TRUNC));

    // Read remaining 5 bytes normally.
    char buf[16] = {};
    iovec iov2{buf, sizeof(buf)};
    msghdr m2{};
    m2.msg_iov = &iov2;
    m2.msg_iovlen = 1;
    EXPECT_EQ(5, recvmsg(t.conn, &m2, 0));
    EXPECT_EQ(0, memcmp(buf, "defgh", 5));

    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, SendIovecConcatenates) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    const char a[] = "AB";
    const char b[] = "CD";
    iovec iov[2] = {{const_cast<char *>(a), 2}, {const_cast<char *>(b), 2}};
    msghdr m{};
    m.msg_iov = iov;
    m.msg_iovlen = 2;
    EXPECT_EQ(4, sendmsg(t.conn, &m, 0));
    close(t.conn);
    close(t.srv);
}

// ---- send to a closed peer -------------------------------------------------

// When the module reports the peer is gone (NFL_CONN_CLOSED), a stream send
// fails with EPIPE and (like Linux) raises SIGPIPE unless MSG_NOSIGNAL is set.
TEST_F(TcpIoTest, StreamSendToClosedPeerRaisesSigpipeAndFailsEpipe) {
    SKIP_IF_NATIVE();  // needs the module to force a closed peer
    auto t = accept_one_loopback();
    module_test_set_send_closed(true);

    g_sigpipe_count = 0;
    struct sigaction sa{};
    sa.sa_handler = count_sigpipe;
    struct sigaction old{};
    ASSERT_EQ(0, sigaction(SIGPIPE, &sa, &old));

    const char data[] = "x";
    EXPECT_LIBC_FAIL(send(t.conn, data, 1, 0), EPIPE);
    EXPECT_EQ(1, g_sigpipe_count);

    ASSERT_EQ(0, sigaction(SIGPIPE, &old, nullptr));
    close(t.conn);
    close(t.srv);
}

// MSG_NOSIGNAL suppresses SIGPIPE, but the send still fails with EPIPE.
TEST_F(TcpIoTest, StreamSendToClosedPeerWithNosignalFailsEpipeNoSigpipe) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    module_test_set_send_closed(true);

    g_sigpipe_count = 0;
    struct sigaction sa{};
    sa.sa_handler = count_sigpipe;
    struct sigaction old{};
    ASSERT_EQ(0, sigaction(SIGPIPE, &sa, &old));

    const char data[] = "x";
    EXPECT_LIBC_FAIL(send(t.conn, data, 1, MSG_NOSIGNAL), EPIPE);
    EXPECT_EQ(0, g_sigpipe_count);

    ASSERT_EQ(0, sigaction(SIGPIPE, &old, nullptr));
    close(t.conn);
    close(t.srv);
}
// ---- peer EOF (half-close) readiness ---------------------------------------
//
// When the module reports the peer closed its end (NFL_CONN_CLOSED), the stream
// socket is at end-of-stream. POSIX/Linux treat that as readable: poll/epoll
// must report POLLIN so the SUT performs the read that returns 0 (EOF) and then
// closes the fd. If readiness stays silent, an epoll-driven SUT (e.g. redis)
// never learns the connection died, never closes it, and every readiness probe
// re-runs nfl_receive on the dead fd, an unbounded busy-spin.

TEST_F(TcpIoTest, PollReportsReadableOnPeerEof) {
    SKIP_IF_NATIVE();  // needs the module to force a peer EOF
    auto t = accept_one_loopback();
    module_test_set_recv_closed(true);

    pollfd pfd{};
    pfd.fd = t.conn;
    pfd.events = POLLIN;
    pfd.revents = 0;
    EXPECT_EQ(1, poll(&pfd, 1, 0)) << "a peer-closed stream socket is readable (EOF)";
    EXPECT_TRUE(pfd.revents & POLLIN);

    char buf[1];
    EXPECT_EQ(0, recv(t.conn, buf, sizeof(buf), 0)) << "the ready poll is followed by a 0-byte EOF read";

    close(t.conn);
    close(t.srv);
}

TEST_F(TcpIoTest, EpollReportsReadableOnPeerEof) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback();
    module_test_set_recv_closed(true);

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev{};
    ev.events = EPOLLIN;  // redis registers EPOLLIN only, not EPOLLRDHUP
    ev.data.fd = t.conn;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, t.conn, &ev));

    epoll_event out[1];
    EXPECT_EQ(1, epoll_wait(ep, out, 1, 0)) << "a peer-closed stream socket is readable (EOF)";
    EXPECT_TRUE(out[0].events & EPOLLIN);

    char buf[1];
    EXPECT_EQ(0, recv(t.conn, buf, sizeof(buf), 0));

    close(ep);
    close(t.conn);
    close(t.srv);
}

// ---- inter-packet gap across poll/select/epoll -----------------------------
//
// The gap a non-blocking recv reports as EAGAIN between two nfl_receive packets
// must also be visible to poll/select/epoll on the same socket, so the readiness
// side and the read side never disagree: a poll that reports readable must be
// followed by a recv that returns data, never a spurious EAGAIN. A timed (would
// block) poll skips the gap so a timeout handler never fires on a packet that is
// really there. See docs/message_boundaries.md.

// A zero-timeout (non-blocking) poll reports the gap as not-ready once between
// packets, then ready; the recv after a ready poll returns the packet.
TEST_F(TcpIoTest, NonblockingPollReportsGapOnceBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback_nonblocking();
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    ASSERT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));  // consume the first packet

    pollfd pfd{};
    pfd.fd = t.conn;
    pfd.events = POLLIN;

    pfd.revents = 0;
    EXPECT_EQ(0, poll(&pfd, 1, 0)) << "the gap: a zero-timeout poll reports not-ready once";

    pfd.revents = 0;
    EXPECT_EQ(1, poll(&pfd, 1, 0)) << "the next poll reports ready";
    EXPECT_TRUE(pfd.revents & POLLIN);

    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0)) << "a ready poll must be followed by a data recv, never EAGAIN";
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

// A poll with a non-zero timeout counts as blocking: it skips the gap, reports
// the next packet ready right away, and the recv that follows returns it.
TEST_F(TcpIoTest, TimedPollSkipsGapBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback_nonblocking();
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    ASSERT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));  // consume the first packet

    pollfd pfd{};
    pfd.fd = t.conn;
    pfd.events = POLLIN;
    pfd.revents = 0;
    EXPECT_EQ(1, poll(&pfd, 1, 100)) << "a timed poll skips the gap and reports ready";
    EXPECT_TRUE(pfd.revents & POLLIN);

    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

// select mirrors poll: a zero-timeout select reports the gap as not-ready once.
TEST_F(TcpIoTest, NonblockingSelectReportsGapOnceBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback_nonblocking();
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    ASSERT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));

    fd_set rfds;
    timeval zero{0, 0};

    FD_ZERO(&rfds);
    FD_SET(t.conn, &rfds);
    EXPECT_EQ(0, select(t.conn + 1, &rfds, nullptr, nullptr, &zero)) << "the gap: a zero-timeout select reports not-ready once";

    FD_ZERO(&rfds);
    FD_SET(t.conn, &rfds);
    EXPECT_EQ(1, select(t.conn + 1, &rfds, nullptr, nullptr, &zero));
    EXPECT_TRUE(FD_ISSET(t.conn, &rfds));

    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

// A select with a non-zero timeout counts as blocking: it skips the gap.
TEST_F(TcpIoTest, TimedSelectSkipsGapBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback_nonblocking();
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    ASSERT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));

    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(t.conn, &rfds);
    timeval tv{0, 100 * 1000};  // 100 ms
    EXPECT_EQ(1, select(t.conn + 1, &rfds, nullptr, nullptr, &tv)) << "a timed select skips the gap and reports ready";
    EXPECT_TRUE(FD_ISSET(t.conn, &rfds));

    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(t.conn);
    close(t.srv);
}

// epoll follows the same rule: a zero-timeout epoll_wait reports the gap (no
// events) once between packets, then the event.
TEST_F(TcpIoTest, NonblockingEpollReportsGapOnceBetweenPackets) {
    SKIP_IF_NATIVE();
    auto t = accept_one_loopback_nonblocking();
    inject_to_loopback_port(t.srv_port, "AAA", 3);
    inject_to_loopback_port(t.srv_port, "BBB", 3);

    char buf[16] = {};
    ASSERT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = t.conn;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, t.conn, &ev));

    epoll_event out[1];
    EXPECT_EQ(0, epoll_wait(ep, out, 1, 0)) << "the gap: a zero-timeout epoll_wait reports no events once";
    EXPECT_EQ(1, epoll_wait(ep, out, 1, 0));

    EXPECT_EQ(3, recv(t.conn, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "BBB", 3));

    close(ep);
    close(t.conn);
    close(t.srv);
}
