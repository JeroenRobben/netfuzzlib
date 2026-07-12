// ioctl(2) on socket fds: FIONBIO, FIONREAD, SIOCGIF* family.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

using namespace nfl_test;

TEST(IoctlTest, FionbioTogglesNonblocking) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    int on = 1;
    ASSERT_EQ(0, ioctl(s, FIONBIO, &on));
    int fl = fcntl(s, F_GETFL);
    EXPECT_TRUE(fl & O_NONBLOCK);

    int off = 0;
    ASSERT_EQ(0, ioctl(s, FIONBIO, &off));
    fl = fcntl(s, F_GETFL);
    EXPECT_FALSE(fl & O_NONBLOCK);

    close(s);
}

TEST(IoctlTest, FionreadOnFreshSocketReturnsZero) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ASSERT_NE(0u, bind_loopback_v4_ephemeral(s));
    int n = -1;
    ASSERT_EQ(0, ioctl(s, FIONREAD, &n));
    EXPECT_EQ(n, 0);
    close(s);
}

TEST(IoctlTest, SiocgifindexLoopbackIsNonZero) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFINDEX, &req));
    EXPECT_NE(req.ifr_ifindex, 0);
    close(s);
}

TEST(IoctlTest, SiocgifnameRoundTripsLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFINDEX, &req));
    const int idx = req.ifr_ifindex;

    ifreq req2{};
    req2.ifr_ifindex = idx;
    ASSERT_EQ(0, ioctl(s, SIOCGIFNAME, &req2));
    EXPECT_STREQ(req2.ifr_name, "lo");
    close(s);
}

TEST(IoctlTest, SiocgifflagsLoopbackHasIffLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFFLAGS, &req));
    EXPECT_TRUE(req.ifr_flags & IFF_LOOPBACK);
    EXPECT_TRUE(req.ifr_flags & IFF_UP);
    close(s);
}

TEST(IoctlTest, SiocgifaddrLoopbackReturns127001) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFADDR, &req));
    auto *sa = reinterpret_cast<sockaddr_in *>(&req.ifr_addr);
    EXPECT_EQ(sa->sin_family, AF_INET);
    EXPECT_EQ(sa->sin_addr.s_addr, htonl(INADDR_LOOPBACK));
    close(s);
}

TEST(IoctlTest, SiocgifindexUnknownIfaceFails) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "definitely-not-an-iface-xy", IFNAMSIZ - 1);
    EXPECT_EQ(-1, ioctl(s, SIOCGIFINDEX, &req));
    close(s);
}

TEST(IoctlTest, SiocgifnetmaskLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFNETMASK, &req));
    auto *sa = reinterpret_cast<sockaddr_in *>(&req.ifr_netmask);
    EXPECT_EQ(sa->sin_family, AF_INET);
    // Loopback is 127.0.0.0/8 → 255.0.0.0.
    EXPECT_EQ(sa->sin_addr.s_addr, htonl(0xff000000));
    close(s);
}

TEST(IoctlTest, SiocgifmtuLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFMTU, &req));
    EXPECT_GT(req.ifr_mtu, 0);
    close(s);
}

TEST(IoctlTest, SiocgifhwaddrLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    ifreq req{};
    strncpy(req.ifr_name, "lo", IFNAMSIZ - 1);
    ASSERT_EQ(0, ioctl(s, SIOCGIFHWADDR, &req));
    // Loopback's link-layer family is ARPHRD_LOOPBACK.
    EXPECT_EQ(req.ifr_hwaddr.sa_family, ARPHRD_LOOPBACK);
    close(s);
}

TEST(IoctlTest, SiocgifconfReturnsAtLeastLoopback) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    char buf[4096];
    ifconf ifc{};
    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    ASSERT_EQ(0, ioctl(s, SIOCGIFCONF, &ifc));
    ASSERT_GE(static_cast<int>(ifc.ifc_len / sizeof(ifreq)), 1);

    bool saw_lo = false;
    const int n = ifc.ifc_len / sizeof(ifreq);
    auto *entries = reinterpret_cast<ifreq *>(ifc.ifc_buf);
    for (int i = 0; i < n; i++) {
        if (strcmp(entries[i].ifr_name, "lo") == 0) {
            saw_lo = true;
            break;
        }
    }
    EXPECT_TRUE(saw_lo);
    close(s);
}
