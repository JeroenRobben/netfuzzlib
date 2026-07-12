// Liveness heuristic: a socket that is polled dry or blocked on with no data
// consults nfl_socket_idle if a module defines it, but netfuzzlib never exits on
// its own. A blocking read returns EINTR and a poll keeps returning no events.
// These behaviours only exist in the model, so every test is nfl-only.

#include "test_helpers.h"

#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

class LivenessTest : public NetIOTest {};

// A blocking read on an idle socket returns EINTR, it does not end the run, even
// while another endpoint still has data queued.
TEST_F(LivenessTest, BlockingRecvSpinsWhileAnotherSocketBusy) {
    SKIP_IF_NATIVE();  // a real blocking recv would block forever here
    auto busy = make_bound_udp_v4();
    ASSERT_GE(busy.fd, 0);
    auto idle = make_bound_udp_v4();
    ASSERT_GE(idle.fd, 0);
    auto tx = make_bound_udp_v4();
    ASSERT_GE(tx.fd, 0);

    // Queue a packet for `busy`, so the process is not fully idle.
    sockaddr_in dst = loopback_v4(busy.port);
    ASSERT_EQ(1, sendto(tx.fd, "x", 1, 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    char buf[8];
    errno = 0;
    const ssize_t r = recv(idle.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(errno, EINTR) << "blocking recv should spin (EINTR), not exit, while a peer is busy";

    close(busy.fd);
    close(idle.fd);
    close(tx.fd);
}

// With nothing left for any socket, a blocking read still returns EINTR rather
// than ending the run. netfuzzlib never exits on its own.
TEST_F(LivenessTest, BlockingRecvSpinsWhenAllIdle) {
    SKIP_IF_NATIVE();
    auto s = make_bound_udp_v4();
    ASSERT_GE(s.fd, 0);

    char buf[8];
    errno = 0;
    const ssize_t r = recv(s.fd, buf, sizeof(buf), 0);
    EXPECT_EQ(r, -1);
    EXPECT_EQ(errno, EINTR) << "blocking recv on a fully idle process should spin (EINTR), not exit";

    close(s.fd);
}

// A socket polled dry over and over keeps reporting no events. There is no
// failsafe that ends the run.
TEST_F(LivenessTest, IdlePollOnSocketNeverExits) {
    SKIP_IF_NATIVE();
    auto s = make_bound_udp_v4();
    ASSERT_GE(s.fd, 0);

    pollfd pfd;
    pfd.fd = s.fd;
    pfd.events = POLLIN;
    for (int i = 0; i < 1000; i++) {
        pfd.revents = 0;
        ASSERT_EQ(0, poll(&pfd, 1, 0)) << "idle poll should report no events, not exit";
    }

    close(s.fd);
}
