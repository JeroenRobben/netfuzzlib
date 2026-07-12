// fcntl(2): F_DUPFD, F_DUPFD_CLOEXEC, F_GETFD/F_SETFD, F_SETFL access-mode preservation.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

TEST(FcntlTest, FDupfdAtMinAssignsAtLeastMin) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int min = s + 100;
    const int dup_fd = fcntl(s, F_DUPFD, min);
    ASSERT_GE(dup_fd, 0);
    EXPECT_GE(dup_fd, min);
    close(dup_fd);
    close(s);
}

TEST(FcntlTest, FDupfdNegativeMinReturnsEinval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LIBC_FAIL(fcntl(s, F_DUPFD, -1), EINVAL);
    close(s);
}

TEST(FcntlTest, FDupfdCloexecSetsCloexecOnNewFd) {
    // The netfuzzlib model has no per-fd FD_CLOEXEC tracking yet, so F_GETFD
    // always returns 0. Mark this as a nfl model gap until per-fd flags land.
    SKIP_IF_NFL();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int dup_fd = fcntl(s, F_DUPFD_CLOEXEC, 0);
    ASSERT_GE(dup_fd, 0);

    int fd_flags = fcntl(dup_fd, F_GETFD);
    ASSERT_GE(fd_flags, 0);
    EXPECT_TRUE(fd_flags & FD_CLOEXEC);

    close(dup_fd);
    close(s);
}

TEST(FcntlTest, FGetfdInitiallyZero) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int fd_flags = fcntl(s, F_GETFD);
    EXPECT_GE(fd_flags, 0);
    EXPECT_EQ(fd_flags & FD_CLOEXEC, 0);
    close(s);
}

TEST(FcntlTest, FSetflPreservesAccessMode) {
    // F_SETFL toggles status flags. Access mode (O_RDWR) is fixed at open()
    // and is unaffected by F_SETFL.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    ASSERT_EQ(fl & O_ACCMODE, O_RDWR);

    ASSERT_EQ(0, fcntl(s, F_SETFL, fl | O_NONBLOCK));
    fl = fcntl(s, F_GETFL);
    EXPECT_EQ(fl & O_ACCMODE, O_RDWR);
    EXPECT_TRUE(fl & O_NONBLOCK);

    close(s);
}

TEST(FcntlTest, FSetfdAndFGetfdRoundTrip) {
    SKIP_IF_NFL();  // model has no per-fd FD_CLOEXEC tracking yet
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_EQ(0, fcntl(s, F_SETFD, FD_CLOEXEC));
    EXPECT_EQ(FD_CLOEXEC, fcntl(s, F_GETFD));
    ASSERT_EQ(0, fcntl(s, F_SETFD, 0));
    EXPECT_EQ(0, fcntl(s, F_GETFD));
    close(s);
}

TEST(FcntlTest, FDupfdMinAboveMaxReturnsEinval) {
    // A min-fd argument greater than RLIMIT_NOFILE/SOCKET_FD_MAX must fail.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    errno = 0;
    const int r = fcntl(s, F_DUPFD, 1 << 30);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(errno == EINVAL || errno == EMFILE) << "errno=" << errno;
    close(s);
}
