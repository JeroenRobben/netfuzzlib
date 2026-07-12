// Tests for dup(2), dup2(2), dup3(2): self-dup, flag validation, the
// "duplicates share state" contract.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

TEST(DupTest, DupReturnsNewFd) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int s2 = dup(s);
    ASSERT_GE(s2, 0);
    EXPECT_NE(s, s2);
    close(s2);
    close(s);
}

TEST(DupTest, Dup2SelfDupReturnsFdUnchanged) {
    // POSIX: dup2(fd, fd) is a no-op when fd is valid, must return fd, not -1.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_EQ(s, dup2(s, s));
    close(s);
}

TEST(DupTest, Dup3RejectsUnknownFlags) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    // dup3 only accepts O_CLOEXEC. Any other flag gives EINVAL.
    EXPECT_LIBC_FAIL(dup3(s, s + 1, O_NONBLOCK), EINVAL);
    close(s);
}

TEST(DupTest, Dup3SelfDupRejectedWithEinval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    // dup3(fd, fd, ...) is required to fail with EINVAL (unlike dup2).
    EXPECT_LIBC_FAIL(dup3(s, s, 0), EINVAL);
    close(s);
}

TEST(DupTest, DupedFdSharesBoundAddr) {
    // The two fds reference the same open description: getsockname on the
    // duplicate returns the same bound address.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    sockaddr_in sa = loopback_v4(0);
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    const int s2 = dup(s);
    ASSERT_GE(s2, 0);

    sockaddr_in bound1{}, bound2{};
    socklen_t len1 = sizeof(bound1), len2 = sizeof(bound2);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&bound1), &len1));
    ASSERT_EQ(0, getsockname(s2, reinterpret_cast<sockaddr *>(&bound2), &len2));
    EXPECT_EQ(bound1.sin_port, bound2.sin_port);
    EXPECT_EQ(bound1.sin_addr.s_addr, bound2.sin_addr.s_addr);

    close(s2);
    close(s);
}

TEST(DupTest, DupOfInvalidFdReturnsEbadf) {
    EXPECT_LIBC_FAIL(dup(99999), EBADF);
}

TEST(DupTest, Dup2OverExistingFdReplacesIt) {
    // dup2(s1, s2): if s2 is open, kernel closes it silently and points it
    // at the same open description as s1.
    const int s1 = socket(AF_INET, SOCK_DGRAM, 0);
    const int s2 = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s1, 0);
    ASSERT_GE(s2, 0);
    EXPECT_EQ(s2, dup2(s1, s2));

    // s2 must now reference the DGRAM socket (same type as s1).
    int type = -1;
    socklen_t len = sizeof(type);
    ASSERT_EQ(0, getsockopt(s2, SOL_SOCKET, SO_TYPE, &type, &len));
    EXPECT_EQ(type, SOCK_DGRAM);
    close(s2);
    close(s1);
}

TEST(DupTest, Dup2NegativeNewfdReturnsError) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    errno = 0;
    EXPECT_EQ(dup2(s, -1), -1);
    EXPECT_TRUE(errno == EBADF || errno == EINVAL) << "errno=" << errno;
    close(s);
}
