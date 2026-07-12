// close(2), close_range(2), closefrom, including the inclusive-bound contract.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

TEST(CloseTest, CloseFreshSocketReturnsZero) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_EQ(0, close(s));
}

// close(-1) is a routine no-op that a real daemon issues on an already-cleared
// fd; the kernel just answers EBADF. netfuzzlib's close() interceptor must do
// the same without indexing its native-fd description cache at [-1], which used
// to read an out-of-bounds pointer and crash in free() from the debug log path.
TEST(CloseTest, CloseNegativeFdReturnsEbadfWithoutCrashing) {
    EXPECT_LIBC_FAIL(close(-1), EBADF);
}

TEST(CloseTest, CloseSameFdTwiceReturnsEbadfOnSecond) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, close(s));
    EXPECT_LIBC_FAIL(close(s), EBADF);
}

TEST(CloseTest, CloseRangeIsInclusiveOnUpperBound) {
    // close_range over [low, high] must treat the upper bound as inclusive.
    const int a = socket(AF_INET, SOCK_DGRAM, 0);
    const int b = socket(AF_INET, SOCK_DGRAM, 0);
    const int c = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(a, 0);
    ASSERT_GE(b, 0);
    ASSERT_GE(c, 0);

    const int low = a < c ? a : c;
    const int high = a > c ? a : c;
    ASSERT_EQ(0, close_range(low, high, 0));

    // All three must now be closed.
    EXPECT_LIBC_FAIL(close(a), EBADF);
    EXPECT_LIBC_FAIL(close(b), EBADF);
    EXPECT_LIBC_FAIL(close(c), EBADF);
}

TEST(CloseTest, CloseRangeOnSingleFdClosesIt) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, close_range(s, s, 0));
    EXPECT_LIBC_FAIL(close(s), EBADF);
}

TEST(CloseTest, CloseRangeCloexecLeavesFdOpen) {
    // CLOSE_RANGE_CLOEXEC marks the fds CLOEXEC instead of closing them.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, close_range(s, s, CLOSE_RANGE_CLOEXEC));
    // Still open after the call.
    int fl = fcntl(s, F_GETFD);
    EXPECT_GE(fl, 0);
    close(s);
}
