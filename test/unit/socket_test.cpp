// Tests for socket(2): creation semantics, blocking flag from SOCK_NONBLOCK,
// SO_DOMAIN/SO_TYPE/SO_PROTOCOL round-trips after creation.

#include "test_helpers.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>

using namespace nfl_test;

TEST(SocketTest, CreateInetStreamReturnsValidFd) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0) << "errno=" << errno;
    EXPECT_EQ(0, close(s));
}

TEST(SocketTest, CreateInetDgramReturnsValidFd) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0) << "errno=" << errno;
    EXPECT_EQ(0, close(s));
}

TEST(SocketTest, CreateInet6StreamReturnsValidFd) {
    const int s = socket(AF_INET6, SOCK_STREAM, 0);
    ASSERT_GE(s, 0) << "errno=" << errno;
    EXPECT_EQ(0, close(s));
}

TEST(SocketTest, FGetFlIncludesAccessMode) {
    // Linux F_GETFL on a socket must include the access mode bits (sockets are
    // O_RDWR). Apps that mask `flags & O_ACCMODE` will see read-only otherwise.
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    const int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    EXPECT_EQ(fl & O_ACCMODE, O_RDWR);
    close(s);
}

TEST(SocketTest, SockNonblockSetsNonblockingFlag) {
    const int s = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(s, 0);
    const int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    EXPECT_TRUE(fl & O_NONBLOCK);
    close(s);
}

TEST(SocketTest, NoNonblockMeansBlocking) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    const int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    EXPECT_FALSE(fl & O_NONBLOCK);
    close(s);
}

TEST(SocketTest, SoDomainReturnsCreationDomain) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int domain = -1;
    socklen_t len = sizeof(domain);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_DOMAIN, &domain, &len));
    EXPECT_EQ(domain, AF_INET);
    EXPECT_EQ(len, sizeof(int));
    close(s);
}

TEST(SocketTest, SoTypeReturnsCreationType) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int type = -1;
    socklen_t len = sizeof(type);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_TYPE, &type, &len));
    EXPECT_EQ(type, SOCK_DGRAM);
    close(s);
}

TEST(SocketTest, SoProtocolReturnsCreationProtocol) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int proto = -1;
    socklen_t len = sizeof(proto);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &proto, &len));
    // Default protocol for SOCK_DGRAM is UDP. Kernel and nfl agree.
    EXPECT_EQ(proto, IPPROTO_UDP);
    close(s);
}

TEST(SocketTest, InvalidDomainReturnsEafnosupport) {
    // socket(2): unknown domain → EAFNOSUPPORT.
    EXPECT_LIBC_FAIL(socket(0xff, SOCK_DGRAM, 0), EAFNOSUPPORT);
}

TEST(SocketTest, InvalidTypeReturnsEinvalOrEsocktnosupport) {
    // socket(2): unknown type → EINVAL on most kernels, ESOCKTNOSUPPORT on
    // some older ones. Accept either.
    errno = 0;
    const int r = socket(AF_INET, 0xff, 0);
    EXPECT_EQ(r, -1);
    EXPECT_TRUE(errno == EINVAL || errno == ESOCKTNOSUPPORT) << "errno=" << errno;
}

TEST(SocketTest, AfUnixForwardsToKernelAndWorks) {
    // netfuzzlib forwards AF_UNIX to native. The result should be a valid fd
    // in both modes (in nfl, fd lands in the native range, NOT the nfl range).
    const int s = socket(AF_UNIX, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    if (kIsNfl) {
        // AF_UNIX is not modeled. The interceptor forwards to the kernel,
        // so the fd must NOT be in netfuzzlib's reserved range.
        EXPECT_LT(s, 70);
    }
    close(s);
}

TEST(SocketTest, SockCloexecSetsCloexec) {
    SKIP_IF_NFL();  // model doesn't track per-fd CLOEXEC yet
    const int s = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ASSERT_GE(s, 0);
    int fd_flags = fcntl(s, F_GETFD);
    EXPECT_TRUE(fd_flags & FD_CLOEXEC);
    close(s);
}

TEST(SocketTest, RawIcmpDgramRequiresPrivilegeOrSucceedsInNfl) {
    // SOCK_DGRAM with IPPROTO_ICMP needs ping_group_range setting on Linux
    // (not always available), but nfl accepts it. Only assert in nfl mode.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    ASSERT_GE(s, 0);
    close(s);
}
