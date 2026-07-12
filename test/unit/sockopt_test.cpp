// Tests for getsockopt(2)/setsockopt(2): SO_RCVTIMEO/SNDTIMEO data type,
// IP_PKTINFO round-trip, ENOPROTOOPT for unknown options, plus broad coverage
// of the per-level WARN_CASE_* dispatch arms in src/core/sockopt.c.

#include "test_helpers.h"

#include <fcntl.h>
#include <linux/netlink.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <vector>

using namespace nfl_test;

TEST(SockoptTest, RcvtimeoSetGetRoundTripsTimeval) {
    // SO_RCVTIMEO uses struct timeval. Storing as int (the previous netfuzzlib
    // bug) would corrupt the round-trip on 64-bit systems.
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    timeval set{};
    set.tv_sec = 3;
    set.tv_usec = 500000;
    ASSERT_EQ(0, setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &set, sizeof(set)));

    timeval got{};
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &got, &len));
    EXPECT_EQ(len, sizeof(timeval));
    EXPECT_EQ(got.tv_sec, set.tv_sec);
    EXPECT_EQ(got.tv_usec, set.tv_usec);
    close(s);
}

TEST(SockoptTest, SndtimeoSetGetRoundTripsTimeval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    timeval set{};
    set.tv_sec = 1;
    set.tv_usec = 250000;
    ASSERT_EQ(0, setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &set, sizeof(set)));

    timeval got{};
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &got, &len));
    EXPECT_EQ(got.tv_sec, set.tv_sec);
    EXPECT_EQ(got.tv_usec, set.tv_usec);
    close(s);
}

TEST(SockoptTest, IpPktinfoRoundTrip) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);

    int on = 1;
    ASSERT_EQ(0, setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)));

    int got = 0;
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, IPPROTO_IP, IP_PKTINFO, &got, &len));
    EXPECT_EQ(got, 1);
    EXPECT_EQ(len, sizeof(int));
    close(s);
}

TEST(SockoptTest, SoErrorIsZeroForFreshSocket) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int err = -1;
    socklen_t len = sizeof(err);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_ERROR, &err, &len));
    EXPECT_EQ(err, 0);
    close(s);
}

TEST(SockoptTest, SoAcceptconnFalseBeforeListen) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    int v = -1;
    socklen_t len = sizeof(v);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_ACCEPTCONN, &v, &len));
    EXPECT_EQ(v, 0);
    close(s);
}

TEST(SockoptTest, FcntlSetFlNonblockToggle) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    EXPECT_FALSE(fl & O_NONBLOCK);

    ASSERT_EQ(0, fcntl(s, F_SETFL, fl | O_NONBLOCK));
    fl = fcntl(s, F_GETFL);
    EXPECT_TRUE(fl & O_NONBLOCK);

    ASSERT_EQ(0, fcntl(s, F_SETFL, fl & ~O_NONBLOCK));
    fl = fcntl(s, F_GETFL);
    EXPECT_FALSE(fl & O_NONBLOCK);
    close(s);
}

TEST(SockoptTest, GetsockoptUnknownReturnsEnoprotoopt) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = sizeof(v);
    EXPECT_LIBC_FAIL(getsockopt(s, SOL_SOCKET, 0xdead, &v, &len),
                     ENOPROTOOPT);
    close(s);
}

TEST(SockoptTest, GetsockoptIntoptionTooSmallBufFails) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = 1;  // too small for an int
    // netfuzzlib's helper enforces *option_len >= sizeof(int) and returns
    // EINVAL. Linux is lax and truncates. Mark this nfl-only.
    SKIP_IF_NATIVE();
    EXPECT_LIBC_FAIL(getsockopt(s, SOL_SOCKET, SO_TYPE, &v, &len),
                     EINVAL);
    close(s);
}

TEST(SockoptTest, SoReuseaddrRoundTrip) {
    // SO_REUSEADDR is a model gap: setsockopt warns and returns ENOPROTOOPT.
    // Skip in nfl until the option is plumbed through.
    SKIP_IF_NFL();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int on = 1;
    ASSERT_EQ(0, setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)));
    int got = 0;
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_REUSEADDR, &got, &len));
    EXPECT_NE(got, 0);
    close(s);
}

TEST(SockoptTest, GetsockoptOnIpProtocolWithMismatchedDomainEinval) {
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = sizeof(v);
    // IPV6 options on an IPv4 socket should fail.
    EXPECT_LIBC_FAIL(getsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &v, &len),
                     EOPNOTSUPP);
    close(s);
}

// ---- valid value getters ---------------------------------------------------

TEST(SockoptTest, SoDomainTypeProtocolReportConfiguredValues) {
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = sizeof(v);

    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_DOMAIN, &v, &len));
    EXPECT_EQ(AF_INET, v);
    len = sizeof(v);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_TYPE, &v, &len));
    EXPECT_EQ(SOCK_STREAM, v);
    len = sizeof(v);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_PROTOCOL, &v, &len));
    EXPECT_TRUE(v == 0 || v == IPPROTO_TCP);
    close(s);
}

TEST(SockoptTest, Ipv6UnicastHopsHasReasonableDefault) {
    SKIP_IF_NATIVE();  // host ttl default varies
    const int s = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = sizeof(v);
    ASSERT_EQ(0, getsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS, &v, &len));
    EXPECT_GT(v, 0);
    close(s);
}

TEST(SockoptTest, Ipv6PktinfoRoundTrip) {
    const int s = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int on = 1;
    ASSERT_EQ(0, setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)));
    int got = 0;
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &got, &len));
    EXPECT_NE(got, 0);
    close(s);
}

TEST(SockoptTest, IpOptionsRoundTrip) {
    SKIP_IF_NATIVE();  // IP_OPTIONS round-trip is model-defined, kernel needs CAP_NET_RAW for some shapes
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const unsigned char opts[] = {0x94, 0x04, 0x00, 0x00};  // IP_OPT_NOP padded
    ASSERT_EQ(0, setsockopt(s, IPPROTO_IP, IP_OPTIONS, opts, sizeof(opts)));
    unsigned char out[16] = {};
    socklen_t len = sizeof(out);
    ASSERT_EQ(0, getsockopt(s, IPPROTO_IP, IP_OPTIONS, out, &len));
    EXPECT_EQ(static_cast<socklen_t>(sizeof(opts)), len);
    EXPECT_EQ(0, memcmp(opts, out, sizeof(opts)));
    close(s);
}

// ---- domain-mismatch errors ------------------------------------------------

TEST(SockoptTest, SetsockoptIpv4OptOnIpv6SockReturnsEinval) {
    SKIP_IF_NATIVE();  // kernel returns ENOPROTOOPT in some cases, model is stricter
    const int s = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int on = 1;
    EXPECT_LIBC_FAIL(setsockopt(s, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on)),
                     EINVAL);
    close(s);
}

TEST(SockoptTest, SetsockoptIpv6OptOnIpv4SockReturnsEinval) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int on = 1;
    EXPECT_LIBC_FAIL(setsockopt(s, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof(on)),
                     EINVAL);
    close(s);
}

TEST(SockoptTest, SetsockoptOnNullBufferReturnsEfault) {
    SKIP_IF_NATIVE();  // kernel may segfault before reaching errno check
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LIBC_FAIL(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, nullptr, sizeof(int)),
                     EFAULT);
    close(s);
}

TEST(SockoptTest, GetsockoptOnNullBufferReturnsEfault) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    socklen_t len = sizeof(int);
    EXPECT_LIBC_FAIL(getsockopt(s, SOL_SOCKET, SO_TYPE, nullptr, &len),
                     EFAULT);
    close(s);
}

// ---- netlink-only options --------------------------------------------------

TEST(SockoptTest, NetlinkAddDropMembershipUpdatesGroupMask) {
    SKIP_IF_NATIVE();  // kernel mutates a real socket, we just verify model state
    const int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    const int group = 1;  // RTMGRP_LINK
    ASSERT_EQ(0, setsockopt(s, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                            &group, sizeof(group)));

    uint32_t got = 0;
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS,
                            &got, &len));
    EXPECT_EQ(1u, got & 0x1u);

    ASSERT_EQ(0, setsockopt(s, SOL_NETLINK, NETLINK_DROP_MEMBERSHIP,
                            &group, sizeof(group)));
    got = 0;
    len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_NETLINK, NETLINK_LIST_MEMBERSHIPS,
                            &got, &len));
    EXPECT_EQ(0u, got & 0x1u);
    close(s);
}

TEST(SockoptTest, NetlinkAddMembershipRejectsOutOfRangeGroup) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    const int bogus = 99;
    EXPECT_LIBC_FAIL(setsockopt(s, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                                &bogus, sizeof(bogus)),
                     EINVAL);
    close(s);
}

TEST(SockoptTest, NetlinkOptOnNonNetlinkSockReturnsEinval) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int group = 1;
    EXPECT_LIBC_FAIL(setsockopt(s, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP,
                                &group, sizeof(group)),
                     EINVAL);
    close(s);
}

// ---- fcntl coverage --------------------------------------------------------

TEST(SockoptTest, FcntlGetflReturnsAccessModeOrdNonblock) {
    const int s = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(s, 0);
    const int fl = fcntl(s, F_GETFL);
    ASSERT_GE(fl, 0);
    EXPECT_TRUE(fl & O_NONBLOCK);
    EXPECT_TRUE((fl & O_ACCMODE) == O_RDWR);
    close(s);
}

TEST(SockoptTest, FcntlDupfdAllocatesNewFd) {
    SKIP_IF_NATIVE();  // F_DUPFD on the model uses our fd table
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int s2 = fcntl(s, F_DUPFD, 0);
    ASSERT_GE(s2, 0);
    EXPECT_NE(s, s2);
    close(s);
    close(s2);
}

TEST(SockoptTest, FcntlDupfdNegativeMinFdReturnsEinval) {
    SKIP_IF_NATIVE();  // kernel returns EINVAL too but the model path is what we want to cover
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_LIBC_FAIL(fcntl(s, F_DUPFD, -1), EINVAL);
    close(s);
}

// ---- broad WARN_CASE_* dispatch coverage -----------------------------------
//
// Each level's getsockopt_print_unsupported_error / setsockopt_print_unsupported_error
// is a flat switch over option codes that just logs a warning and falls
// through. To cover the arms we just need to exercise each option name once.
// Single test per level, looping over the option list, keeps the ctest
// listing tidy while still hitting every WARN_CASE line. nfl-only because
// the real kernel happily handles many of these and returns 0.

namespace {

void expect_unsupported_get(int level, std::initializer_list<int> opts, int domain = AF_INET) {
    int v = 0;
    socklen_t len = sizeof(v);
    int s = -1;
    if (level == SOL_NETLINK) {
        s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    } else {
        s = socket(domain, SOCK_DGRAM, 0);
    }
    ASSERT_GE(s, 0);
    for (int opt : opts) {
        len = sizeof(v);
        const int rc = getsockopt(s, level, opt, &v, &len);
        EXPECT_EQ(-1, rc) << "getsockopt level=" << level << " opt=" << opt
                          << " unexpectedly succeeded";
        EXPECT_EQ(ENOPROTOOPT, errno);
    }
    close(s);
}

void expect_unsupported_set(int level, std::initializer_list<int> opts, int domain = AF_INET) {
    int on = 1;
    int s = -1;
    if (level == SOL_NETLINK) {
        s = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    } else {
        s = socket(domain, SOCK_DGRAM, 0);
    }
    ASSERT_GE(s, 0);
    for (int opt : opts) {
        const int rc = setsockopt(s, level, opt, &on, sizeof(on));
        EXPECT_EQ(-1, rc) << "setsockopt level=" << level << " opt=" << opt
                          << " unexpectedly succeeded";
        EXPECT_EQ(ENOPROTOOPT, errno);
    }
    close(s);
}

}  // namespace

TEST(SockoptTest, UnsupportedSolSocketOptionsAllReturnEnoprotoopt) {
    SKIP_IF_NATIVE();
    expect_unsupported_get(SOL_SOCKET, {
        SO_KEEPALIVE, SO_BROADCAST, SO_DEBUG, SO_DONTROUTE, SO_LINGER,
        SO_OOBINLINE, SO_RCVLOWAT, SO_SNDLOWAT,
        SO_PASSCRED, SO_PEERCRED, SO_PRIORITY, SO_REUSEPORT, SO_TIMESTAMP,
        SO_TIMESTAMPNS, SO_BUSY_POLL, SO_MARK, SO_INCOMING_CPU,
        SO_BINDTODEVICE, SO_PEEK_OFF,
        SO_SELECT_ERR_QUEUE, SO_RXQ_OVFL, SO_LOCK_FILTER,
        SO_ATTACH_FILTER, SO_DETACH_FILTER,
    });
    /* SO_REUSEADDR / SO_REUSEPORT / SO_KEEPALIVE / SO_BROADCAST /
     * SO_DONTROUTE / SO_LINGER are deliberately NOT in this list:
     * setsockopt accepts them silently (see SetAcceptedAsNoop sibling
     * tests, same rationale as the buffer-size hints). */
    expect_unsupported_set(SOL_SOCKET, {
        SO_DEBUG,
        SO_OOBINLINE, SO_RCVLOWAT, SO_SNDLOWAT,
        SO_PASSCRED, SO_PRIORITY, SO_TIMESTAMP, SO_TIMESTAMPNS,
        SO_BUSY_POLL, SO_MARK, SO_BINDTODEVICE, SO_PEEK_OFF,
        SO_SELECT_ERR_QUEUE, SO_RXQ_OVFL,
        SO_LOCK_FILTER, SO_ATTACH_FILTER, SO_DETACH_FILTER,
    });
}

TEST(SockoptTest, KeepAliveAndBroadcastSetAcceptedAsNoop) {
    // live555's RTSPServer aborts startup with "failed to set keep alive:
    // Protocol not available" if SO_KEEPALIVE returns ENOPROTOOPT. Many
    // daemons set SO_BROADCAST unconditionally before any send. Same
    // pragmatic rationale as SO_REUSEADDR, accept silently. getsockopt
    // is still unsupported.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int on = 1;
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_BROADCAST, &on, sizeof(on)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_DONTROUTE, &on, sizeof(on)));
    close(s);
}

TEST(SockoptTest, LingerSetAcceptedAsNoop) {
    // dcmqrscp aborts with "TCP Initialization Error: Protocol not
    // available" on SO_LINGER returning ENOPROTOOPT. The model has
    // no close-time queue to drain, accept silently. Note: the
    // option value is `struct linger`, not int.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(s, 0);
    struct linger lg = { .l_onoff = 1, .l_linger = 0 };
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_LINGER, &lg, sizeof(lg)));
    close(s);
}

TEST(SockoptTest, BufferSizeOptionsAcceptedAsNoop) {
    SKIP_IF_NATIVE();  // model has no real buffers, native value would differ
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 1 << 17;  // 128KB
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_SNDBUFFORCE, &v, sizeof(v)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_RCVBUFFORCE, &v, sizeof(v)));

    int got = 0;
    socklen_t len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_SNDBUF, &got, &len));
    EXPECT_GT(got, 0);  // plausible default reported back
    len = sizeof(got);
    ASSERT_EQ(0, getsockopt(s, SOL_SOCKET, SO_RCVBUF, &got, &len));
    EXPECT_GT(got, 0);
    close(s);
}

TEST(SockoptTest, ReuseAddrAndReusePortSetAcceptedAsNoop) {
    // Daemons (dnsmasq, bftpd, lightftp, …) set these unconditionally and
    // some (like dnsmasq) bail out on ENOPROTOOPT. The model has a
    // single binding namespace, so the flags are semantic no-ops. Accept
    // them silently. getsockopt is still unsupported.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int on = 1;
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)));
    EXPECT_EQ(0, setsockopt(s, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)));
    close(s);
}

TEST(SockoptTest, TcpLevelOptionsAcceptedAsNoop) {
    // OpenSSL's BIO_connect calls setsockopt(IPPROTO_TCP, TCP_NODELAY) before
    // connect() and aborts ("BIO_connect: unable to nodelay") on ENOPROTOOPT,
    // so any TLS client running under nfl needs setsockopt at the TCP level
    // to succeed. The model has no real TCP stack, so NODELAY / congestion
    // control / keepalive timers don't change observable behaviour, so accept
    // silently as a no-op (same rationale as the SOL_SOCKET buffer-size and
    // reuse-flag siblings above). getsockopt at this level remains unsupported.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_GE(s, 0);
    const int on = 1;
    EXPECT_EQ(0, setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)));
    EXPECT_EQ(0, setsockopt(s, IPPROTO_TCP, TCP_KEEPIDLE, &on, sizeof(on)));
    EXPECT_EQ(0, setsockopt(s, IPPROTO_TCP, TCP_QUICKACK, &on, sizeof(on)));
    close(s);
}

TEST(SockoptTest, TcpLevelSetTooSmallReturnsEinval) {
    // The TCP-level no-op path still validates option_len like the buffer-size
    // siblings, passing < sizeof(int) must fail with EINVAL, not silently
    // succeed. Catches a regression where the length check is dropped.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    ASSERT_GE(s, 0);
    const int on = 1;
    EXPECT_LIBC_FAIL(setsockopt(s, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(char)),
                     EINVAL);
    close(s);
}

TEST(SockoptTest, UnsupportedIpOptionsAllReturnEnoprotoopt) {
    SKIP_IF_NATIVE();
    expect_unsupported_get(IPPROTO_IP, {
        IP_TOS, IP_TTL, IP_HDRINCL, IP_RECVTTL, IP_RECVTOS, IP_RECVERR,
        IP_RECVOPTS, IP_RETOPTS, IP_MULTICAST_IF, IP_MULTICAST_TTL,
        IP_MULTICAST_LOOP, IP_MULTICAST_ALL, IP_ADD_MEMBERSHIP,
        IP_DROP_MEMBERSHIP, IP_FREEBIND, IP_MTU, IP_MTU_DISCOVER,
        IP_NODEFRAG, IP_PASSSEC, IP_RECVORIGDSTADDR, IP_ROUTER_ALERT,
        IP_TRANSPARENT, IP_BIND_ADDRESS_NO_PORT,
    });
    /* IP_MULTICAST_IF / IP_MULTICAST_LOOP / IP_MULTICAST_TTL are
     * deliberately NOT in this set list. setsockopt accepts them
     * silently as no-ops. See MulticastSetAcceptedAsNoop sibling.
     * Same for IP_TOS / IP_MTU_DISCOVER. See TosAndMtuDiscoverSetAcceptedAsNoop. */
    expect_unsupported_set(IPPROTO_IP, {
        IP_TTL, IP_HDRINCL, IP_RECVTTL, IP_RECVTOS, IP_RECVERR,
        IP_RECVOPTS, IP_RETOPTS, IP_MULTICAST_ALL, IP_FREEBIND, IP_MTU,
        IP_NODEFRAG, IP_PASSSEC, IP_RECVORIGDSTADDR,
        IP_ROUTER_ALERT, IP_TRANSPARENT, IP_BIND_ADDRESS_NO_PORT,
    });
}

TEST(SockoptTest, TosAndMtuDiscoverSetAcceptedAsNoop) {
    // kamailio's udp_init() sets IP_TOS and IP_MTU_DISCOVER on every UDP
    // socket and treats ENOPROTOOPT on the latter as fatal ("IPv4
    // setsockopt: Protocol not available"). The model has no real packet
    // path, so both are observable no-ops.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int tos = 0x10;
    EXPECT_EQ(0, setsockopt(s, IPPROTO_IP, IP_TOS, &tos, sizeof(tos)));
    const int pmtud = IP_PMTUDISC_DONT;
    EXPECT_EQ(0, setsockopt(s, IPPROTO_IP, IP_MTU_DISCOVER,
                            &pmtud, sizeof(pmtud)));
    close(s);
}

TEST(SockoptTest, MulticastSetAcceptedAsNoop) {
    // live555's GroupsockHelper sets IP_MULTICAST_LOOP/TTL on every
    // UDP socket it opens (even unicast RTP/RTCP) and treats
    // ENOPROTOOPT as a "this socket is broken, retry" signal, a
    // tight loop. Accept silently. IP_MULTICAST_IF takes a struct
    // (in_addr or ip_mreqn), not int, so any non-empty buffer is OK.
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    const int loop_on = 1;
    EXPECT_EQ(0, setsockopt(s, IPPROTO_IP, IP_MULTICAST_LOOP,
                            &loop_on, sizeof(loop_on)));
    const int ttl = 4;
    EXPECT_EQ(0, setsockopt(s, IPPROTO_IP, IP_MULTICAST_TTL,
                            &ttl, sizeof(ttl)));
    struct in_addr any = { .s_addr = htonl(INADDR_ANY) };
    EXPECT_EQ(0, setsockopt(s, IPPROTO_IP, IP_MULTICAST_IF,
                            &any, sizeof(any)));
    close(s);
}

TEST(SockoptTest, UnsupportedIpv6OptionsAllReturnEnoprotoopt) {
    SKIP_IF_NATIVE();
    expect_unsupported_get(IPPROTO_IPV6, {
        IPV6_V6ONLY, IPV6_MTU, IPV6_MTU_DISCOVER, IPV6_MULTICAST_HOPS,
        IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_RTHDR, IPV6_AUTHHDR,
        IPV6_DSTOPTS, IPV6_HOPOPTS, IPV6_HOPLIMIT, IPV6_RECVERR,
        IPV6_ROUTER_ALERT, IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP,
    }, AF_INET6);
    /* IPV6_V6ONLY is deliberately NOT in the set list: the model is
     * V6ONLY-by-default (separate v4/v6 binding namespaces), so we
     * accept the setsockopt as a no-op. getsockopt is still unsupported. */
    expect_unsupported_set(IPPROTO_IPV6, {
        IPV6_MTU, IPV6_MTU_DISCOVER, IPV6_MULTICAST_HOPS,
        IPV6_MULTICAST_IF, IPV6_MULTICAST_LOOP, IPV6_RTHDR, IPV6_AUTHHDR,
        IPV6_DSTOPTS, IPV6_HOPOPTS, IPV6_HOPLIMIT, IPV6_RECVERR,
        IPV6_ROUTER_ALERT, IPV6_ADD_MEMBERSHIP, IPV6_DROP_MEMBERSHIP,
        IPV6_ADDRFORM,
    }, AF_INET6);
}

TEST(SockoptTest, UnsupportedNetlinkOptionsAllReturnEnoprotoopt) {
    SKIP_IF_NATIVE();
    expect_unsupported_get(SOL_NETLINK, {
        NETLINK_PKTINFO, NETLINK_BROADCAST_ERROR, NETLINK_NO_ENOBUFS,
        NETLINK_CAP_ACK, NETLINK_EXT_ACK, NETLINK_GET_STRICT_CHK,
    });
    expect_unsupported_set(SOL_NETLINK, {
        NETLINK_PKTINFO, NETLINK_BROADCAST_ERROR, NETLINK_NO_ENOBUFS,
        NETLINK_LISTEN_ALL_NSID, NETLINK_CAP_ACK, NETLINK_EXT_ACK,
        NETLINK_GET_STRICT_CHK,
    });
}

TEST(SockoptTest, UnknownLevelReturnsEnoprotoopt) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    int v = 0;
    socklen_t len = sizeof(v);
    EXPECT_LIBC_FAIL(getsockopt(s, 0xbeef, 1, &v, &len), ENOPROTOOPT);
    EXPECT_LIBC_FAIL(setsockopt(s, 0xbeef, 1, &v, sizeof(v)), ENOPROTOOPT);
    close(s);
}
