// UDP send/recv tests that exercise the data path. Both modes use loopback:
// native mode uses the real kernel, nfl mode uses module-test's loopback
// packet queue. Same test code, same expectations on both.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <climits>
#include <cstdlib>
#include <cstring>

using namespace nfl_test;

class UdpIoTest : public NetIOTest {};

TEST_F(UdpIoTest, SendtoAndRecvLoopback) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "hello world";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ssize_t sent = sendto(send_sock.fd, msg, sizeof(msg), 0,
                          reinterpret_cast<sockaddr *>(&dst), sizeof(dst));
    EXPECT_EQ(sent, static_cast<ssize_t>(sizeof(msg)));

    char buf[64] = {};
    ssize_t got = recv(recv_sock.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(msg)));
    EXPECT_STREQ(buf, msg);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, RecvfromReportsSenderAddr) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "from-sender";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char buf[64] = {};
    sockaddr_in from{};
    socklen_t fromlen = sizeof(from);
    ssize_t got = recvfrom(recv_sock.fd, buf, sizeof(buf), 0,
                           reinterpret_cast<sockaddr *>(&from), &fromlen);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(msg)));
    EXPECT_EQ(fromlen, sizeof(sockaddr_in));
    EXPECT_EQ(from.sin_family, AF_INET);
    EXPECT_EQ(from.sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    EXPECT_EQ(ntohs(from.sin_port), send_sock.port);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, MsgPeekDoesNotConsumeDatagram) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "peek-me";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char buf1[64] = {};
    char buf2[64] = {};
    ssize_t r1 = recv(recv_sock.fd, buf1, sizeof(buf1), MSG_PEEK);
    ssize_t r2 = recv(recv_sock.fd, buf2, sizeof(buf2), 0);
    EXPECT_EQ(r1, static_cast<ssize_t>(sizeof(msg)));
    EXPECT_EQ(r2, static_cast<ssize_t>(sizeof(msg)));
    EXPECT_EQ(0, memcmp(buf1, buf2, sizeof(msg)));
    EXPECT_STREQ(buf2, msg);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, ShortRecvBufferTruncatesAndSetsMsgTrunc) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "abcdefghij";  // 11 bytes incl NUL
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char small_buf[4] = {};
    iovec iov{small_buf, sizeof(small_buf)};
    msghdr m{};
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    ssize_t got = recvmsg(recv_sock.fd, &m, 0);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(small_buf)));
    EXPECT_TRUE(m.msg_flags & MSG_TRUNC);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, MsgTruncFlagReturnsFullDatagramSize) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "0123456789abcdef";  // 17 bytes
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char small_buf[4] = {};
    // With MSG_TRUNC, recv returns the full datagram length even though only
    // sizeof(small_buf) bytes are actually written.
    ssize_t got = recv(recv_sock.fd, small_buf, sizeof(small_buf), MSG_TRUNC);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(msg)));

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, NonblockingRecvWithNoDataReturnsMinusOneEagain) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);

    int fl = fcntl(recv_sock.fd, F_GETFL);
    ASSERT_GE(fl, 0);
    ASSERT_EQ(0, fcntl(recv_sock.fd, F_SETFL, fl | O_NONBLOCK));

    char buf[16] = {};
    EXPECT_LIBC_FAIL(recv(recv_sock.fd, buf, sizeof(buf), 0), EAGAIN);

    close(recv_sock.fd);
}

TEST_F(UdpIoTest, ConnectThenWriteDeliversToPeer) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    sockaddr_in peer = loopback_v4(recv_sock.port);
    ASSERT_EQ(0, connect(send_sock.fd, reinterpret_cast<sockaddr *>(&peer), sizeof(peer)));

    const char msg[] = "via-write";
    ssize_t sent = write(send_sock.fd, msg, sizeof(msg));
    EXPECT_EQ(sent, static_cast<ssize_t>(sizeof(msg)));

    char buf[64] = {};
    ssize_t got = read(recv_sock.fd, buf, sizeof(buf));
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(msg)));
    EXPECT_STREQ(buf, msg);

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, SendWithoutDestinationOnUnconnectedSockReturnsEdestaddrreq) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(fd));

    const char msg[] = "no-dest";
    EXPECT_LIBC_FAIL(send(fd, msg, sizeof(msg), 0), EDESTADDRREQ);
    close(fd);
}

TEST_F(UdpIoTest, IovecSendAndRecv) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char part1[] = "abc";
    const char part2[] = "DEF";
    iovec siov[2] = {
        {const_cast<char *>(part1), sizeof(part1) - 1},
        {const_cast<char *>(part2), sizeof(part2) - 1},
    };
    sockaddr_in dst = loopback_v4(recv_sock.port);
    msghdr smh{};
    smh.msg_name = &dst;
    smh.msg_namelen = sizeof(dst);
    smh.msg_iov = siov;
    smh.msg_iovlen = 2;

    ASSERT_EQ(6, sendmsg(send_sock.fd, &smh, 0));

    char buf[16] = {};
    ssize_t got = recv(recv_sock.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, 6);
    EXPECT_EQ(0, memcmp(buf, "abcDEF", 6));

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, RecvWithNullAddrIgnoresIt) {
    // recvfrom(2) allows NULL src_addr / addrlen, the call should still copy
    // the payload, just without reporting the sender.
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    const char msg[] = "x";
    sockaddr_in dst = loopback_v4(recv_sock.port);
    ASSERT_EQ(static_cast<ssize_t>(sizeof(msg)),
              sendto(send_sock.fd, msg, sizeof(msg), 0,
                     reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char buf[8] = {};
    EXPECT_EQ(static_cast<ssize_t>(sizeof(msg)),
              recvfrom(recv_sock.fd, buf, sizeof(buf), 0, nullptr, nullptr));
    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, MultipleDatagramsAreDeliveredInOrder) {
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    sockaddr_in dst = loopback_v4(recv_sock.port);
    for (int i = 0; i < 3; i++) {
        char m[2] = {static_cast<char>('A' + i), '\0'};
        ASSERT_EQ(2, sendto(send_sock.fd, m, 2, 0,
                            reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    }

    char buf[2];
    ASSERT_EQ(2, recv(recv_sock.fd, buf, 2, 0));
    EXPECT_EQ(buf[0], 'A');
    ASSERT_EQ(2, recv(recv_sock.fd, buf, 2, 0));
    EXPECT_EQ(buf[0], 'B');
    ASSERT_EQ(2, recv(recv_sock.fd, buf, 2, 0));
    EXPECT_EQ(buf[0], 'C');

    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, ZeroLengthDatagramRoundTrip) {
    // UDP allows zero-length datagrams, so recv returns 0 with no error and the
    // packet is consumed.
    auto recv_sock = make_bound_udp_v4();
    ASSERT_GE(recv_sock.fd, 0);
    auto send_sock = make_bound_udp_v4();
    ASSERT_GE(send_sock.fd, 0);

    sockaddr_in dst = loopback_v4(recv_sock.port);
    EXPECT_EQ(0, sendto(send_sock.fd, "", 0, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char buf[1];
    EXPECT_EQ(0, recv(recv_sock.fd, buf, sizeof(buf), 0));
    close(send_sock.fd);
    close(recv_sock.fd);
}

TEST_F(UdpIoTest, WritevConcatenatesChunks) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    char a[] = "abc";
    char b[] = "DEFG";
    char c[] = "12";
    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(0, connect(tx.fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    iovec iov[3] = {
        {a, 3},
        {b, 4},
        {c, 2},
    };
    ssize_t sent = writev(tx.fd, iov, 3);
    EXPECT_EQ(sent, 9);

    char buf[16] = {};
    ssize_t got = recv(rx.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, 9);
    EXPECT_EQ(0, memcmp(buf, "abcDEFG12", 9));

    close(rx.fd);
    close(tx.fd);
}

TEST_F(UdpIoTest, ReadvScattersDatagramAcrossBuffers) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    sockaddr_in dst = loopback_v4(rx.port);
    const char payload[] = "ABCDEFGHIJ";
    ASSERT_EQ(10, sendto(tx.fd, payload, 10, 0,
                         reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char p1[4] = {}, p2[4] = {}, p3[4] = {};
    iovec iov[3] = {{p1, 4}, {p2, 4}, {p3, 4}};
    ssize_t got = readv(rx.fd, iov, 3);
    EXPECT_EQ(got, 10);
    EXPECT_EQ(0, memcmp(p1, "ABCD", 4));
    EXPECT_EQ(0, memcmp(p2, "EFGH", 4));
    EXPECT_EQ(0, memcmp(p3, "IJ", 2));

    close(rx.fd);
    close(tx.fd);
}

TEST_F(UdpIoTest, SendfileFromTempFileToUdpSocket) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    // Stage a backing file with known contents.
    char path[] = "/tmp/nfl_sendfile_XXXXXX";
    int file_fd = mkstemp(path);
    ASSERT_GE(file_fd, 0);
    const char payload[] = "sendfile-payload";
    ASSERT_EQ(static_cast<ssize_t>(sizeof(payload) - 1),
              write(file_fd, payload, sizeof(payload) - 1));
    ASSERT_EQ(0, lseek(file_fd, 0, SEEK_SET));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(0, connect(tx.fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    off_t off = 0;
    ssize_t sent = sendfile(tx.fd, file_fd, &off, sizeof(payload) - 1);
    EXPECT_EQ(sent, static_cast<ssize_t>(sizeof(payload) - 1));
    EXPECT_EQ(off, static_cast<off_t>(sizeof(payload) - 1));

    char buf[64] = {};
    ssize_t got = recv(rx.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(payload) - 1));
    EXPECT_EQ(0, memcmp(buf, payload, sizeof(payload) - 1));

    close(file_fd);
    unlink(path);
    close(rx.fd);
    close(tx.fd);
}

// sendfile(2) may transfer fewer bytes than requested, and the kernel never
// sizes a buffer to `count`. A count far above what any allocation could serve
// must still send the file rather than fail.
TEST_F(UdpIoTest, SendfileWithHugeCountSendsAvailableBytes) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    char path[] = "/tmp/nfl_sendfile_huge_XXXXXX";
    int file_fd = mkstemp(path);
    ASSERT_GE(file_fd, 0);
    const char payload[] = "sendfile-payload";
    ASSERT_EQ(static_cast<ssize_t>(sizeof(payload) - 1),
              write(file_fd, payload, sizeof(payload) - 1));
    ASSERT_EQ(0, lseek(file_fd, 0, SEEK_SET));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(0, connect(tx.fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    off_t off = 0;
    ssize_t sent = sendfile(tx.fd, file_fd, &off, SSIZE_MAX);
    EXPECT_EQ(sent, static_cast<ssize_t>(sizeof(payload) - 1));
    EXPECT_EQ(off, static_cast<off_t>(sizeof(payload) - 1));

    char buf[64] = {};
    ssize_t got = recv(rx.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(got, static_cast<ssize_t>(sizeof(payload) - 1));
    EXPECT_EQ(0, memcmp(buf, payload, sizeof(payload) - 1));

    close(file_fd);
    unlink(path);
    close(rx.fd);
    close(tx.fd);
}

TEST_F(UdpIoTest, SendmmsgDeliversAllDatagramsInOrder) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    sockaddr_in dst = loopback_v4(rx.port);
    const char *payloads[3] = {"alpha", "beta", "gamma"};
    iovec iovs[3];
    mmsghdr msgs[3];
    memset(msgs, 0, sizeof(msgs));
    for (int i = 0; i < 3; i++) {
        iovs[i].iov_base = const_cast<char *>(payloads[i]);
        iovs[i].iov_len = strlen(payloads[i]);
        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &dst;
        msgs[i].msg_hdr.msg_namelen = sizeof(dst);
    }
    int sent = sendmmsg(tx.fd, msgs, 3, 0);
    EXPECT_EQ(sent, 3);
    for (int i = 0; i < 3; i++) {
        EXPECT_EQ(msgs[i].msg_len, strlen(payloads[i]));
    }
    for (int i = 0; i < 3; i++) {
        char buf[32] = {};
        ssize_t got = recv(rx.fd, buf, sizeof(buf), 0);
        EXPECT_EQ(got, static_cast<ssize_t>(strlen(payloads[i])));
        EXPECT_EQ(0, memcmp(buf, payloads[i], got));
    }

    close(rx.fd);
    close(tx.fd);
}