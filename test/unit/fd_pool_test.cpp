// netfuzzlib holds every fd number it hands out for modelled sockets open on
// /dev/null, so the kernel can never give the same number to the SUT. A number
// is claimed lazily the first time a socket needs it and returned to the pool
// (placeholder still open) on close. nfl_reserve_fd_pool() preclaims a block up
// front for a forking symbolic executor that cannot roll the process-global
// kernel fd table back per state.

#include "test_helpers.h"

#include <algorithm>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cerrno>
#include <vector>

using namespace nfl_test;

extern "C" int close_range(unsigned int, unsigned int, int);
// Preclaim a block of modelled-socket fd numbers up front (native stub in
// test_helpers.cpp).
extern "C" void nfl_reserve_fd_pool(int count);

namespace {

// open() is not intercepted, so real files get real kernel fds.
std::vector<int> open_many(int n) {
    std::vector<int> fds;
    for (int i = 0; i < n; i++) {
        int f = open("/dev/zero", O_RDONLY);
        if (f < 0) break;
        fds.push_back(f);
    }
    return fds;
}

void close_all(std::vector<int> &fds) {
    for (int f : fds) close(f);
}

}  // namespace

class FdPoolTest : public NetIOTest {};

// The bug this exists for: with ~67 files open the SUT's next real fd used to
// land on a modelled socket's number, and its read() was routed into the model.
TEST_F(FdPoolTest, SocketFdNeverAliasesALiveKernelFd) {
    auto files = open_many(120);
    ASSERT_GE(files.size(), 100u);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    for (int f : files) {
        EXPECT_NE(f, s) << "socket fd " << s << " aliases a live kernel fd";
    }
    close(s);
    close_all(files);
}

// The reserved numbers must stay reserved once a modelled socket is closed,
// otherwise the alias comes back on the next open(). Unlike the kernel, which
// legitimately recycles a closed fd number, nfl only frees the fd_table slot,
// the /dev/null placeholder underneath stays open for the life of the process.
TEST_F(FdPoolTest, ClosedSocketFdIsNotHandedToTheKernel) {
    SKIP_IF_NATIVE();
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, close(s));

    auto files = open_many(120);
    for (int f : files) {
        EXPECT_NE(f, s) << "a closed socket's fd number leaked to open()";
    }
    close_all(files);
}

// A reserved number the SUT never opened is not a valid fd for it to close.
TEST_F(FdPoolTest, ClosingAnUnopenedReservedFdFailsWithEbadf) {
    SKIP_IF_NATIVE();
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, close(s));  // number returns to the pool, still held natively
    EXPECT_LIBC_FAIL(close(s), EBADF);
}

// Reservation is lazy: a modelled socket claims its /dev/null placeholder the
// first time it needs one, so a target can hold far more sockets than the old
// fixed 256-fd pool, bounded only by the fd table and RLIMIT_NOFILE.
TEST_F(FdPoolTest, ManyConcurrentSocketsBeyondLegacyPoolSize) {
    std::vector<int> socks;
    for (int i = 0; i < 400; i++) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) break;
        socks.push_back(s);
    }
    EXPECT_GT(socks.size(), 300u) << "lazy pool should grow past the legacy 256 cap";
    for (int s : socks) close(s);
}

// Preregistering claims the fd numbers up front, so a socket created after the
// SUT has opened many files reuses a reserved low number instead of being pushed
// above them. Lazily (no preregister) the socket would land above every file.
TEST_F(FdPoolTest, PreregisteredSocketReusesReservedNumberAfterFilesOpen) {
    SKIP_IF_NATIVE();
    nfl_reserve_fd_pool(64);

    auto files = open_many(200);
    ASSERT_GE(files.size(), 100u);
    int max_file = 0;
    for (int f : files) max_file = std::max(max_file, f);

    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LT(s, max_file) << "socket did not reuse a preclaimed fd number";
    for (int f : files) EXPECT_NE(f, s) << "socket aliased a live file fd";

    close(s);
    close_all(files);
}

// Daemon fd hygiene must close the SUT's own fds without releasing the
// placeholders, otherwise the next open() aliases a modelled socket.
TEST_F(FdPoolTest, CloseRangeDoesNotReleaseReservedFds) {
    SKIP_IF_NATIVE();
    pid_t pid = fork();
    ASSERT_GE(pid, 0);
    if (pid == 0) {
        int s = socket(AF_INET, SOCK_DGRAM, 0);
        if (s < 0) _exit(10);
        close_range(3, 999, 0);  // sweeps straight across the reserved pool

        // Whatever the SUT opens now must not land on a socket fd number.
        int s2 = socket(AF_INET, SOCK_DGRAM, 0);
        if (s2 < 0) _exit(11);
        for (int i = 0; i < 200; i++) {
            int f = open("/dev/zero", O_RDONLY);
            if (f < 0) break;
            if (f == s2) _exit(12);  // aliased a live modelled socket
        }
        _exit(0);
    }
    int status = 0;
    ASSERT_EQ(pid, waitpid(pid, &status, 0));
    ASSERT_TRUE(WIFEXITED(status));
    EXPECT_EQ(0, WEXITSTATUS(status)) << "close_range released the reserved fd pool";
}
