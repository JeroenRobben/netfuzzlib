// epoll family tests covering readiness on watched UDP sockets, EEXIST/ENOENT/EINVAL
// edge cases, and the rule that I/O on an epoll fd itself is invalid.

#include "test_helpers.h"

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

class EpollTest : public NetIOTest {};

TEST_F(EpollTest, EpollWaitFiresOnPendingDatagram) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = rx.fd;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    sockaddr_in dst = loopback_v4(rx.port);
    const char payload[] = "ping";
    ASSERT_EQ(4, sendto(tx.fd, payload, 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    epoll_event out[4] = {};
    int n = epoll_wait(ep, out, 4, /*timeout_ms=*/100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(out[0].data.fd, rx.fd);
    EXPECT_TRUE(out[0].events & EPOLLIN);

    close(ep);
    close(rx.fd);
    close(tx.fd);
}

TEST_F(EpollTest, EpollCtlAddTwiceFailsWithEEXIST) {
    auto sock = make_bound_udp_v4();
    ASSERT_GE(sock.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, sock.fd, &ev));
    EXPECT_LIBC_FAIL(epoll_ctl(ep, EPOLL_CTL_ADD, sock.fd, &ev), EEXIST);
    close(ep);
    close(sock.fd);
}

TEST_F(EpollTest, EpollCtlDelOnUnknownFailsWithENOENT) {
    auto sock = make_bound_udp_v4();
    ASSERT_GE(sock.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    EXPECT_LIBC_FAIL(epoll_ctl(ep, EPOLL_CTL_DEL, sock.fd, nullptr), ENOENT);
    close(ep);
    close(sock.fd);
}

TEST_F(EpollTest, EpollCreateZeroSizeFailsWithEINVAL) {
    EXPECT_LIBC_FAIL(epoll_create(0), EINVAL);
}

TEST_F(EpollTest, ReadOnEpollFdFailsWithEINVAL) {
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    char buf[8];
    EXPECT_LIBC_FAIL(read(ep, buf, sizeof(buf)), EINVAL);
    close(ep);
}

TEST_F(EpollTest, EpollWaitWithNoWatchesReturnsZero) {
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event out[1] = {};
    EXPECT_EQ(0, epoll_wait(ep, out, 1, /*timeout_ms=*/0));
    close(ep);
}

TEST_F(EpollTest, EpollCtlAddNativePipeFdSucceeds) {
    // Real-Linux event-loop daemons (redis ae, libevent in memcached/libcoap)
    // register an internal pipe/eventfd into their epoll for cross-thread
    // wakeups. The nfl epoll forwards those onto a shadow kernel epoll.
    SKIP_IF_NATIVE();
    int p[2];
    ASSERT_EQ(0, pipe(p));
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = p[0];
    EXPECT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev));
    EXPECT_EQ(0, epoll_ctl(ep, EPOLL_CTL_DEL, p[0], nullptr));
    close(ep);
    close(p[0]); close(p[1]);
}

TEST_F(EpollTest, EpollWaitFiresOnPendingPipeWrite) {
    // Native fd readiness: write a byte to the pipe, expect EPOLLIN on the
    // read end via the same epoll instance an nfl SUT would use.
    SKIP_IF_NATIVE();
    int p[2];
    ASSERT_EQ(0, pipe(p));
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.fd = p[0];
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev));
    ASSERT_EQ(1, write(p[1], "x", 1));
    epoll_event out[2] = {};
    int n = epoll_wait(ep, out, 2, 0);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(out[0].data.fd, p[0]);
    EXPECT_TRUE(out[0].events & EPOLLIN);
    close(ep);
    close(p[0]); close(p[1]);
}

TEST_F(EpollTest, EpollWaitMixedNflAndNativeFiresBoth) {
    // The use case: a redis-shaped daemon with one nfl UDP socket plus one
    // native control pipe in the same epoll. Both pending → both surface
    // in a single epoll_wait call.
    SKIP_IF_NATIVE();
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    int p[2];
    ASSERT_EQ(0, pipe(p));

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev_sock = {};
    ev_sock.events = EPOLLIN;
    ev_sock.data.u64 = 0xAAAA;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev_sock));

    epoll_event ev_pipe = {};
    ev_pipe.events = EPOLLIN;
    ev_pipe.data.u64 = 0xBBBB;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev_pipe));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    ASSERT_EQ(1, write(p[1], "x", 1));

    epoll_event out[4] = {};
    int n = epoll_wait(ep, out, 4, 0);
    EXPECT_EQ(n, 2);
    bool saw_sock = false, saw_pipe = false;
    for (int i = 0; i < n; i++) {
        if (out[i].data.u64 == 0xAAAA) saw_sock = true;
        if (out[i].data.u64 == 0xBBBB) saw_pipe = true;
    }
    EXPECT_TRUE(saw_sock);
    EXPECT_TRUE(saw_pipe);

    close(ep);
    close(rx.fd); close(tx.fd);
    close(p[0]); close(p[1]);
}
