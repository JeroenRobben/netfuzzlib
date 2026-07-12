// epoll semantics that the flat-watch-array model used to get wrong: watch
// lifetime across close()/dup(), EPOLLET/EPOLLONESHOT arming, cycle rejection,
// fairness between nfl and native watches, and that an idle epoll_wait never
// exits on its own.
//
// Every assertion encodes real-Linux behaviour, so tests_native is the oracle:
// a failure there means the test is wrong, not the model.

#include "test_helpers.h"

#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>

extern "C" int close_range(unsigned int, unsigned int, int);
extern "C" void nfl_reserve_fd_pool(int count);

using namespace nfl_test;

class EpollSemanticsTest : public NetIOTest {};

// ---------------------------------------------------------------------------
// 1. close(fd) must drop fd from every epoll interest set.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, ClosedFdIsRemovedFromInterestSet) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.u64 = 0xDEAD;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));
    ASSERT_EQ(0, close(rx.fd));

    // Nothing is registered any more -> no events, ever.
    epoll_event out[4] = {};
    EXPECT_EQ(0, epoll_wait(ep, out, 4, 0));
    close(ep);
}

// 1b. The dangerous variant: the fd number gets recycled by a *new* socket.
// Real epoll keys the interest set on the open file description, so the new
// socket is unwatched. A model keyed on the integer fd will silently deliver
// the old watch's user data for the new socket.
TEST_F(EpollSemanticsTest, RecycledFdDoesNotInheritStaleWatch) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.u64 = 0xDEAD;  // stands in for a `struct conn *` the SUT will free
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    const int old_fd = rx.fd;
    ASSERT_EQ(0, close(rx.fd));

    auto rx2 = make_bound_udp_v4();
    ASSERT_GE(rx2.fd, 0);
    if (rx2.fd != old_fd) {
        close(rx2.fd); close(ep);
        GTEST_SKIP() << "fd not recycled; nothing to test";
    }

    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);
    sockaddr_in dst = loopback_v4(rx2.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    epoll_event out[4] = {};
    int n = epoll_wait(ep, out, 4, 0);
    // rx2 was never registered. Reporting it (worse, reporting it with
    // 0xDEAD) hands the SUT a dangling pointer.
    EXPECT_EQ(0, n) << "stale watch fired for a recycled fd";

    close(rx2.fd); close(tx.fd); close(ep);
}

// ---------------------------------------------------------------------------
// 2. EPOLLONESHOT: disarm after one delivery.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, OneshotDisarmsAfterFirstDelivery) {
    auto rx = make_bound_udp_v4();
    auto tx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0); ASSERT_GE(tx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN | EPOLLONESHOT;
    ev.data.fd = rx.fd;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    epoll_event out[2] = {};
    ASSERT_EQ(1, epoll_wait(ep, out, 2, 0));
    // Datagram deliberately left unread. Level-triggered would refire, but
    // ONESHOT must not, until EPOLL_CTL_MOD re-arms.
    EXPECT_EQ(0, epoll_wait(ep, out, 2, 0)) << "ONESHOT did not disarm";

    close(ep); close(rx.fd); close(tx.fd);
}

// ---------------------------------------------------------------------------
// 3. EPOLLET: edge, not level.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, EdgeTriggeredReadFiresOnceWithoutNewData) {
    auto rx = make_bound_udp_v4();
    auto tx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0); ASSERT_GE(tx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN | EPOLLET;
    ev.data.fd = rx.fd;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    epoll_event out[2] = {};
    ASSERT_EQ(1, epoll_wait(ep, out, 2, 0));
    EXPECT_EQ(0, epoll_wait(ep, out, 2, 0)) << "ET refired with no new edge";

    close(ep); close(rx.fd); close(tx.fd);
}

// The practical hazard: EPOLLOUT|EPOLLET on a connected socket. A socket is
// almost always writable, so if ET degrades to LT the SUT's event loop spins
// at 100% CPU forever. ET must fire once per edge, not once per call.
TEST_F(EpollSemanticsTest, EdgeTriggeredWriteDoesNotSpin) {
    auto s = make_bound_udp_v4();
    auto peer = make_bound_udp_v4();
    ASSERT_GE(s.fd, 0); ASSERT_GE(peer.fd, 0);
    sockaddr_in dst = loopback_v4(peer.port);
    ASSERT_EQ(0, connect(s.fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLOUT | EPOLLET;
    ev.data.fd = s.fd;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, s.fd, &ev));

    epoll_event out[2] = {};
    ASSERT_EQ(1, epoll_wait(ep, out, 2, 0));  // one writability edge
    int refires = 0;
    for (int i = 0; i < 5; i++) {
        refires += epoll_wait(ep, out, 2, 0);
    }
    EXPECT_EQ(0, refires) << "EPOLLOUT|EPOLLET refired " << refires
                          << "x -> busy-spin in the SUT event loop";
    close(ep); close(s.fd); close(peer.fd);
}

// ---------------------------------------------------------------------------
// 4. Cycles between epoll instances must be rejected with ELOOP.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, MutualNestingRejectedWithELOOP) {
    int a = epoll_create1(0);
    int b = epoll_create1(0);
    ASSERT_GE(a, 0); ASSERT_GE(b, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(a, EPOLL_CTL_ADD, b, &ev));
    // Closing the cycle would make epoll_wait(a) recurse forever.
    EXPECT_LIBC_FAIL(epoll_ctl(b, EPOLL_CTL_ADD, a, &ev), ELOOP);

    close(a); close(b);
}

// 4b. Crash regression: rejecting the cycle is what keeps epoll_wait bounded.
// Accepting it made epoll_wait recurse a <-> b until the stack died (SIGSEGV).
TEST_F(EpollSemanticsTest, CycleRejectionKeepsEpollWaitBounded) {
    int a = epoll_create1(0);
    int b = epoll_create1(0);
    ASSERT_GE(a, 0); ASSERT_GE(b, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(a, EPOLL_CTL_ADD, b, &ev));
    (void)epoll_ctl(b, EPOLL_CTL_ADD, a, &ev);  // must not close the cycle
    epoll_event out[2] = {};
    EXPECT_EQ(0, epoll_wait(a, out, 2, 0));
    close(a); close(b);
}

// Self-add is EINVAL, and a dup'd epoll fd shares the description so it is
// still a self-add, not a two-node cycle.
TEST_F(EpollSemanticsTest, SelfAddRejectedEvenThroughDup) {
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    EXPECT_LIBC_FAIL(epoll_ctl(ep, EPOLL_CTL_ADD, ep, &ev), EINVAL);

    int dupd = dup(ep);
    ASSERT_GE(dupd, 0);
    EXPECT_LIBC_FAIL(epoll_ctl(ep, EPOLL_CTL_ADD, dupd, &ev), EINVAL);
    close(dupd); close(ep);
}

// A watch is registered on the description, not the fd number, so it survives
// the fd it was added under being closed while a dup keeps the description
// alive, exactly as an epitem survives until the last fd of the file closes.
TEST_F(EpollSemanticsTest, WatchSurvivesCloseWhileDupKeepsDescriptionAlive) {
    auto rx = make_bound_udp_v4();
    auto tx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0); ASSERT_GE(tx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);

    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.u64 = 0xCAFE;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    int dupd = dup(rx.fd);
    ASSERT_GE(dupd, 0);
    ASSERT_EQ(0, close(rx.fd));  // description still alive via dupd

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    epoll_event out[2] = {};
    ASSERT_EQ(1, epoll_wait(ep, out, 2, 0)) << "watch dropped though dup kept it alive";
    EXPECT_EQ(out[0].data.u64, 0xCAFEu);

    close(dupd); close(tx.fd); close(ep);
}

// ---------------------------------------------------------------------------
// 5. Fairness: a ready fd must not be starved by other ready fds.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, ReadyNflFdIsNotStarvedByReadyNativeFds) {
    SKIP_IF_NATIVE();  // needs the nfl/native split to be meaningful
    auto rx = make_bound_udp_v4();
    auto tx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0); ASSERT_GE(tx.fd, 0);

    int p1[2], p2[2];
    ASSERT_EQ(0, pipe(p1));
    ASSERT_EQ(0, pipe(p2));
    ASSERT_EQ(1, write(p1[1], "x", 1));
    ASSERT_EQ(1, write(p2[1], "x", 1));

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ev.data.u64 = 0xAAAA;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));
    ev.data.u64 = 0xB1; ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p1[0], &ev));
    ev.data.u64 = 0xB2; ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p2[0], &ev));

    sockaddr_in dst = loopback_v4(rx.port);
    ASSERT_EQ(4, sendto(tx.fd, "ping", 4, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    // 3 ready fds, room for 2 per call. The nfl socket must surface within a
    // few rounds. The kernel requeues delivered LT fds at the ready-list tail.
    bool saw_sock = false;
    for (int round = 0; round < 10 && !saw_sock; round++) {
        epoll_event out[2] = {};
        int n = epoll_wait(ep, out, 2, 0);
        for (int i = 0; i < n; i++) {
            if (out[i].data.u64 == 0xAAAA) saw_sock = true;
        }
    }
    EXPECT_TRUE(saw_sock) << "nfl socket starved by always-ready native fds";

    close(ep); close(rx.fd); close(tx.fd);
    close(p1[0]); close(p1[1]); close(p2[0]); close(p2[1]);
}

// ---------------------------------------------------------------------------
// 6. An epoll fd is readable-when-ready, never writable.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, EpollFdIsNeverWritable) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));

    struct pollfd pfd = {ep, POLLIN | POLLOUT, 0};
    ASSERT_GE(poll(&pfd, 1, 0), 0);
    EXPECT_FALSE(pfd.revents & POLLOUT) << "epoll fd reported writable";

    close(ep); close(rx.fd);
}

// 6b. An epoll fd nested in poll() is readable when *any* watch is ready,
// including a watch registered for EPOLLOUT only.
TEST_F(EpollSemanticsTest, EpollFdReadableWhenOnlyWriteWatchIsReady) {
    auto s = make_bound_udp_v4();
    auto peer = make_bound_udp_v4();
    ASSERT_GE(s.fd, 0); ASSERT_GE(peer.fd, 0);
    sockaddr_in dst = loopback_v4(peer.port);
    ASSERT_EQ(0, connect(s.fd, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLOUT;  // writability only
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, s.fd, &ev));

    struct pollfd pfd = {ep, POLLIN, 0};
    ASSERT_GE(poll(&pfd, 1, 0), 0);
    EXPECT_TRUE(pfd.revents & POLLIN)
        << "epoll fd not readable though a watched fd is writable";

    close(ep); close(s.fd); close(peer.fd);
}

// ---------------------------------------------------------------------------
// 8. An idle epoll_wait never exits on its own. Every epoll_wait path keeps
//    reporting no events and lets the target keep running.
// ---------------------------------------------------------------------------

// An idle nfl watch: epoll_wait keeps returning no events, no exit.
TEST_F(EpollSemanticsTest, IdleEpollOnNflWatchNeverExits) {
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {}; ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev));
    epoll_event out[2] = {};
    for (int i = 0; i < 1000; i++) {
        ASSERT_EQ(0, epoll_wait(ep, out, 2, 0)) << "idle epoll_wait should report no events, not exit";
    }
    close(ep); close(rx.fd);
}

// An epoll instance holding only native watches: still no events, no exit.
TEST_F(EpollSemanticsTest, IdleEpollOnNativeWatchNeverExits) {
    int p[2];
    ASSERT_EQ(0, pipe(p));
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {}; ev.events = EPOLLIN;
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev));  // never written to
    epoll_event out[2] = {};
    for (int i = 0; i < 1000; i++) {
        ASSERT_EQ(0, epoll_wait(ep, out, 2, 0)) << "idle epoll_wait should report no events, not exit";
    }
    close(ep); close(p[0]); close(p[1]);
}

// Likewise for an epoll instance with no watches at all.
TEST_F(EpollSemanticsTest, IdleEpollOnEmptyEpollNeverExits) {
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event out[2] = {};
    for (int i = 0; i < 1000; i++) {
        ASSERT_EQ(0, epoll_wait(ep, out, 2, 0)) << "idle epoll_wait should report no events, not exit";
    }
    close(ep);
}

// ---------------------------------------------------------------------------
// 9. netfuzzlib's own fds live at >= NFL_RESERVED_FD_START (1000) so the
//    close()/closefrom() interceptors can protect them. The shadow epoll fd
//    is allocated by epoll_create1_native() and lands in the SUT's low fd
//    range instead, and a daemon doing fd hygiene destroys it.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, ShadowEpollFdSurvivesDaemonFdHygiene) {
    SKIP_IF_NATIVE();
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        int p[2];
        if (pipe(p) != 0) _exit(10);
        int ep = epoll_create1(0);
        if (ep < 0) _exit(11);
        epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = p[0];
        if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) != 0) _exit(12);  // shadow now exists
        /* Daemon fd hygiene over everything above the pipe. An unrelocated
         * shadow sits right here, the kernel handed it the next free fd. */
        close_range(p[1] + 1, 69, 0);
        if (write(p[1], "x", 1) != 1) _exit(13);
        epoll_event out[2] = {};
        _exit(epoll_wait(ep, out, 2, 0) == 1 ? 0 : 14);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status))
        << "shadow epoll fd was collateral damage of the SUT closing its own fds";
}

// 9c. The shadow kernel epoll fd is created only when a native fd is registered.
// An epoll that only ever watches nfl fds (the only kind that exists under a
// forking symbolic executor) must create no shadow fd, however many the SUT
// makes. With the pool preclaimed up front, the modelled fds draw on the reserved
// numbers rather than dup'ing new placeholders, so a low fd limit leaves only the
// shadow fds as a possible source of allocation: if any were created, the 100
// epolls would blow past the limit.
TEST_F(EpollSemanticsTest, NflOnlyEpollCreatesNoShadowKernelFd) {
    SKIP_IF_NATIVE();
    auto rx = make_bound_udp_v4();
    ASSERT_GE(rx.fd, 0);
    nfl_reserve_fd_pool(150);  // preclaim as a forking-executor harness would

    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        struct rlimit rl = {32, 32};
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) _exit(20);
        epoll_event ev = {};
        ev.events = EPOLLIN;
        for (int i = 0; i < 100; i++) {
            int ep = epoll_create1(0);
            if (ep < 0) _exit(21);
            if (epoll_ctl(ep, EPOLL_CTL_ADD, rx.fd, &ev) != 0) _exit(22);
        }
        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status)) << "nfl-only epoll created a shadow kernel fd";
    close(rx.fd);
}

// 9b. The shadow fd is relocated with F_DUPFD, which fails with EINVAL once its
// base reaches RLIMIT_NOFILE. A default container's soft limit is 1024, so a
// base above that breaks every epoll-backed event loop while still passing on a
// dev box with a high limit. Pin the container's limit here.
TEST_F(EpollSemanticsTest, EpollWorksUnderContainerFdLimit) {
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        struct rlimit rl = {1024, 1024};
        if (setrlimit(RLIMIT_NOFILE, &rl) != 0) _exit(20);
        int ep = epoll_create1(EPOLL_CLOEXEC);
        if (ep < 0) _exit(21);
        int p[2];
        if (pipe(p) != 0) _exit(22);
        epoll_event ev = {};
        ev.events = EPOLLIN;
        ev.data.fd = p[0];
        if (epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev) != 0) _exit(23);
        if (write(p[1], "x", 1) != 1) _exit(24);
        epoll_event out[2] = {};
        _exit(epoll_wait(ep, out, 2, 0) == 1 ? 0 : 25);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status)) << "epoll unusable under a 1024 fd limit";
}

// ---------------------------------------------------------------------------
// 7. Probing an epoll fd for readiness must not consume its events.
// ---------------------------------------------------------------------------
TEST_F(EpollSemanticsTest, PollingEpollFdDoesNotConsumeEvents) {
    SKIP_IF_NATIVE();
    int p[2];
    ASSERT_EQ(0, pipe(p));
    int ep = epoll_create1(0);
    ASSERT_GE(ep, 0);
    epoll_event ev = {};
    ev.events = EPOLLIN | EPOLLET;  // edge: consuming the event destroys it
    ev.data.fd = p[0];
    ASSERT_EQ(0, epoll_ctl(ep, EPOLL_CTL_ADD, p[0], &ev));
    ASSERT_EQ(1, write(p[1], "x", 1));

    struct pollfd pfd = {ep, POLLIN, 0};
    ASSERT_GE(poll(&pfd, 1, 0), 0);
    ASSERT_TRUE(pfd.revents & POLLIN);

    epoll_event out[2] = {};
    EXPECT_EQ(1, epoll_wait(ep, out, 2, 0))
        << "readiness probe swallowed the pending event";

    close(ep); close(p[0]); close(p[1]);
}
