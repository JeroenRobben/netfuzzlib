// rtnetlink: socket creation, bind auto-pid, RTM_GETLINK / RTM_GETADDR /
// RTM_GETROUTE dump structure (NLMSG_DONE termination, every response a valid
// nlmsghdr), single-target lookups, and request validation.

#include "test_helpers.h"

extern "C" {
// Defined in routing_test.cpp's native-mode stub block (one binary, one
// definition), declared here so RTM_GETROUTE tests can install a gateway.
int nfl_set_ipv4_default_gateway(const char *gateway_addr_text,
                                 unsigned int device_index);
int nfl_set_ipv6_default_gateway(const char *gateway_addr_text,
                                 unsigned int device_index);
}

#if defined(NFL_TEST_NATIVE_MODE)
extern "C" {
int nfl_set_ipv6_default_gateway(const char *, unsigned int) { return -1; }
}
#endif

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

using namespace nfl_test;

namespace {

// Send a netlink request `payload` of `payload_len` bytes (including the
// nlmsghdr) on `fd`.
ssize_t nl_send_request(int fd, const void *payload, size_t payload_len) {
    sockaddr_nl kernel{};
    kernel.nl_family = AF_NETLINK;
    iovec iov{const_cast<void *>(payload), payload_len};
    msghdr m{};
    m.msg_name = &kernel;
    m.msg_namelen = sizeof(kernel);
    m.msg_iov = &iov;
    m.msg_iovlen = 1;
    return sendmsg(fd, &m, 0);
}

// Receive netlink messages on `fd` until NLMSG_DONE or NLMSG_ERROR. Collects
// each response message body into `out` (caller can inspect types/contents).
struct NlMessage {
    std::vector<char> bytes;  // full nlmsghdr + payload
    nlmsghdr *hdr() { return reinterpret_cast<nlmsghdr *>(bytes.data()); }
};

bool nl_read_dump(int fd, std::vector<NlMessage> &out, std::string &err) {
    char buf[16384];
    for (;;) {
        ssize_t n = recv(fd, buf, sizeof(buf), 0);
        if (n < 0) {
            err = std::string("recv: errno=") + std::to_string(errno);
            return false;
        }
        nlmsghdr *h = reinterpret_cast<nlmsghdr *>(buf);
        for (; NLMSG_OK(h, n); h = NLMSG_NEXT(h, n)) {
            NlMessage m;
            m.bytes.assign(reinterpret_cast<char *>(h),
                           reinterpret_cast<char *>(h) + h->nlmsg_len);
            const auto type = h->nlmsg_type;
            out.push_back(std::move(m));
            if (type == NLMSG_DONE) {
                return true;
            }
            if (type == NLMSG_ERROR) {
                err = "received NLMSG_ERROR";
                return false;
            }
        }
    }
}

int open_netlink_route() {
    return socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
}

}  // namespace

TEST(NetlinkTest, SocketIsCreatable) {
    const int s = open_netlink_route();
    ASSERT_GE(s, 0) << "errno=" << errno;
    close(s);
}

TEST(NetlinkTest, BindWithZeroPidAssignsUniquePid) {
    // Linux: passing nl_pid=0 to bind() asks the kernel to auto-assign a
    // unique non-zero port id. getsockname returns that value.
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = 0;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    sockaddr_nl bound{};
    socklen_t len = sizeof(bound);
    ASSERT_EQ(0, getsockname(s, reinterpret_cast<sockaddr *>(&bound), &len));
    EXPECT_EQ(bound.nl_family, AF_NETLINK);
    EXPECT_NE(bound.nl_pid, 0u);
    close(s);
}

TEST(NetlinkTest, GetlinkDumpEndsWithNlmsgDone) {
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    struct {
        nlmsghdr hdr;
        ifinfomsg info;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.info.ifi_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().hdr()->nlmsg_type, NLMSG_DONE);
    close(s);
}

TEST(NetlinkTest, GetlinkDumpIncludesLoopback) {
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    struct {
        nlmsghdr hdr;
        ifinfomsg info;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.info.ifi_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_lo = false;
    for (auto &m : msgs) {
        nlmsghdr *h = m.hdr();
        if (h->nlmsg_type != RTM_NEWLINK) {
            continue;
        }
        ifinfomsg *info = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(h));
        int len = static_cast<int>(h->nlmsg_len - NLMSG_LENGTH(sizeof(*info)));
        for (rtattr *rta = IFLA_RTA(info); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
            if (rta->rta_type == IFLA_IFNAME &&
                strncmp(reinterpret_cast<char *>(RTA_DATA(rta)), "lo",
                        RTA_PAYLOAD(rta)) == 0) {
                saw_lo = true;
                break;
            }
        }
    }
    EXPECT_TRUE(saw_lo) << "loopback link not found in RTM_GETLINK dump";
    close(s);
}

TEST(NetlinkTest, GetaddrDumpFindsLoopbackV4) {
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    struct {
        nlmsghdr hdr;
        rtgenmsg gen;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.gen.rtgen_family = AF_INET;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_loopback_v4 = false;
    for (auto &m : msgs) {
        nlmsghdr *h = m.hdr();
        if (h->nlmsg_type != RTM_NEWADDR) {
            continue;
        }
        ifaddrmsg *ifa = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(h));
        if (ifa->ifa_family != AF_INET) {
            continue;
        }
        int len = static_cast<int>(h->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa)));
        for (rtattr *rta = IFA_RTA(ifa); RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
            if (rta->rta_type == IFA_ADDRESS && RTA_PAYLOAD(rta) == 4) {
                uint32_t a;
                memcpy(&a, RTA_DATA(rta), 4);
                if (a == htonl(INADDR_LOOPBACK)) {
                    saw_loopback_v4 = true;
                    break;
                }
            }
        }
    }
    EXPECT_TRUE(saw_loopback_v4) << "127.0.0.1 not found in RTM_GETADDR dump";
    close(s);
}

TEST(NetlinkTest, GetlinkDumpEntriesHaveNlmFMulti) {
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    struct {
        nlmsghdr hdr;
        ifinfomsg info;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.info.ifi_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;
    // Every RTM_NEWLINK entry in a dump must carry NLM_F_MULTI.
    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type == RTM_NEWLINK) {
            EXPECT_TRUE(m.hdr()->nlmsg_flags & NLM_F_MULTI)
                << "RTM_NEWLINK in dump must have NLM_F_MULTI set";
        }
    }
    close(s);
}

TEST(NetlinkTest, GetneighDumpReachesNlmsgDone) {
    // Even when there are no neighbours to report, the dump must terminate
    // with NLMSG_DONE so the caller doesn't block forever.
    const int s = open_netlink_route();
    ASSERT_GE(s, 0);
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    ASSERT_EQ(0, bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)));

    struct {
        nlmsghdr hdr;
        ndmsg nd;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.nd.ndm_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().hdr()->nlmsg_type, NLMSG_DONE);
    close(s);
}

namespace {

// Open + bind an rtnetlink socket. Returns -1 on failure.
int open_bound_netlink() {
    const int s = open_netlink_route();
    if (s < 0) return -1;
    sockaddr_nl sa{};
    sa.nl_family = AF_NETLINK;
    if (bind(s, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0) {
        close(s);
        return -1;
    }
    return s;
}

}  // namespace

// ---- RTM_GETLINK single-target paths --------------------------------------

TEST(NetlinkTest, GetlinkByIndexReturnsSingleEntry) {
    // ifi_index != 0 + no NLM_F_DUMP → single-target lookup. Must return
    // exactly one RTM_NEWLINK for the matching device, no NLMSG_DONE
    // (single-shot replies don't terminate with DONE per kernel convention).
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);
    const int lo_idx = static_cast<int>(if_nametoindex("lo"));
    ASSERT_GT(lo_idx, 0);

    struct {
        nlmsghdr hdr;
        ifinfomsg info;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST;  /* not a dump */
    req.hdr.nlmsg_seq = 1;
    req.info.ifi_family = AF_UNSPEC;
    req.info.ifi_index = lo_idx;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    char buf[8192];
    const ssize_t n = recv(s, buf, sizeof(buf), 0);
    ASSERT_GT(n, 0);
    auto *h = reinterpret_cast<nlmsghdr *>(buf);
    ASSERT_TRUE(NLMSG_OK(h, n));
    EXPECT_EQ(static_cast<unsigned int>(RTM_NEWLINK), h->nlmsg_type);
    auto *ifinfo = reinterpret_cast<ifinfomsg *>(NLMSG_DATA(h));
    EXPECT_EQ(lo_idx, ifinfo->ifi_index);
    close(s);
}

TEST(NetlinkTest, GetlinkByIndexNotFoundReturnsEnodev) {
    SKIP_IF_NATIVE();  // kernel may return a different errno depending on namespace state
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        ifinfomsg info;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST;
    req.hdr.nlmsg_seq = 1;
    req.info.ifi_family = AF_UNSPEC;
    req.info.ifi_index = 9999;  // not present in test module

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    char buf[1024];
    const ssize_t n = recv(s, buf, sizeof(buf), 0);
    ASSERT_GT(n, 0);
    auto *h = reinterpret_cast<nlmsghdr *>(buf);
    ASSERT_EQ(static_cast<unsigned int>(NLMSG_ERROR), h->nlmsg_type);
    auto *e = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(h));
    EXPECT_EQ(-ENODEV, e->error);
    close(s);
}

TEST(NetlinkTest, GetlinkShortRequestReturnsEinval) {
    // A request whose payload is shorter than struct ifinfomsg is malformed, so
    // the model must reply with NLMSG_ERROR / -EINVAL rather than dereferencing.
    // Native kernel silently drops malformed headers (no reply at all), which
    // would hang recv, so nfl-only.
    SKIP_IF_NATIVE();
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    nlmsghdr hdr{};
    hdr.nlmsg_len = NLMSG_LENGTH(0);  /* header only, no ifinfomsg */
    hdr.nlmsg_type = RTM_GETLINK;
    hdr.nlmsg_flags = NLM_F_REQUEST;
    hdr.nlmsg_seq = 1;

    ASSERT_GT(nl_send_request(s, &hdr, hdr.nlmsg_len), 0);

    char buf[1024];
    const ssize_t n = recv(s, buf, sizeof(buf), 0);
    ASSERT_GT(n, 0);
    auto *h = reinterpret_cast<nlmsghdr *>(buf);
    ASSERT_EQ(static_cast<unsigned int>(NLMSG_ERROR), h->nlmsg_type);
    auto *e = reinterpret_cast<nlmsgerr *>(NLMSG_DATA(h));
    EXPECT_EQ(-EINVAL, e->error);
    close(s);
}

// ---- RTM_GETADDR family filtering -----------------------------------------

TEST(NetlinkTest, GetaddrFamilyFilterIpv4OnlyExcludesIpv6) {
    // rtgen_family=AF_INET → only IPv4 addresses in the response. Use the
    // model's eth0 (192.0.2.1 v4 + 2001:db8::1 v6) as the contrast: with the
    // filter set, the v6 address must not appear.
    SKIP_IF_NATIVE();  // host topology varies, nfl gives a deterministic mix
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtgenmsg gen;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETADDR;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.gen.rtgen_family = AF_INET;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_v4 = false;
    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type != RTM_NEWADDR) continue;
        auto *ifa = reinterpret_cast<ifaddrmsg *>(NLMSG_DATA(m.hdr()));
        EXPECT_NE(AF_INET6, ifa->ifa_family) << "filter rtgen_family=AF_INET leaked an IPv6 entry";
        if (ifa->ifa_family == AF_INET) saw_v4 = true;
    }
    EXPECT_TRUE(saw_v4) << "expected at least one IPv4 entry";
    close(s);
}

// ---- RTM_GETROUTE ---------------------------------------------------------

TEST(NetlinkTest, GetrouteDumpEndsWithNlmsgDone) {
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtmsg rt;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.rt.rtm_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;
    ASSERT_FALSE(msgs.empty());
    EXPECT_EQ(msgs.back().hdr()->nlmsg_type, NLMSG_DONE);
    close(s);
}

TEST(NetlinkTest, GetrouteDumpEmitsConnectedRouteForLoopback) {
    // The model's `lo` carries 127.0.0.1/8, so the dump must include a connected
    // route (RTM_NEWROUTE, scope=LINK, dst_len=8) for it.
    SKIP_IF_NATIVE();
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtmsg rt;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.rt.rtm_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_lo_connected = false;
    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type != RTM_NEWROUTE) continue;
        auto *rt = reinterpret_cast<rtmsg *>(NLMSG_DATA(m.hdr()));
        if (rt->rtm_family == AF_INET && rt->rtm_dst_len == 8 &&
            rt->rtm_scope == RT_SCOPE_LINK) {
            saw_lo_connected = true;
        }
    }
    EXPECT_TRUE(saw_lo_connected) << "expected a 127.0.0.0/8 connected route";
    close(s);
}

TEST(NetlinkTest, GetrouteFamilyFilterIpv4OnlyExcludesIpv6) {
    SKIP_IF_NATIVE();
    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtmsg rt;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.rt.rtm_family = AF_INET;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type != RTM_NEWROUTE) continue;
        auto *rt = reinterpret_cast<rtmsg *>(NLMSG_DATA(m.hdr()));
        EXPECT_NE(AF_INET6, rt->rtm_family) << "rtm_family=AF_INET filter leaked an IPv6 route";
    }
    close(s);
}

TEST(NetlinkTest, GetrouteWithIpv6DefaultGatewayEmitsDefaultRoute) {
    // Mirror of the IPv4 sibling: install an IPv6 default gateway and verify
    // the RTM_GETROUTE dump includes a v6 default route.
    SKIP_IF_NATIVE();
    const int eth0_idx = static_cast<int>(if_nametoindex("eth0"));
    ASSERT_GT(eth0_idx, 0);
    ASSERT_EQ(0, nfl_set_ipv6_default_gateway("2001:db8::fe", eth0_idx));

    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtmsg rt;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.rt.rtm_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_default = false;
    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type != RTM_NEWROUTE) continue;
        auto *rt = reinterpret_cast<rtmsg *>(NLMSG_DATA(m.hdr()));
        if (rt->rtm_family == AF_INET6 && rt->rtm_dst_len == 0 &&
            rt->rtm_scope == RT_SCOPE_UNIVERSE) {
            saw_default = true;
        }
    }
    EXPECT_TRUE(saw_default) << "expected an IPv6 default route after gateway install";
    close(s);
}

TEST(NetlinkTest, GetrouteWithDefaultGatewayEmitsDefaultRoute) {
    // After installing an IPv4 default gateway via the public API, the
    // route dump must include a default route (dst_len=0, scope=UNIVERSE).
    SKIP_IF_NATIVE();
    const int eth0_idx = static_cast<int>(if_nametoindex("eth0"));
    ASSERT_GT(eth0_idx, 0);
    ASSERT_EQ(0, nfl_set_ipv4_default_gateway("192.0.2.254", eth0_idx));

    const int s = open_bound_netlink();
    ASSERT_GE(s, 0);

    struct {
        nlmsghdr hdr;
        rtmsg rt;
    } req{};
    req.hdr.nlmsg_len = sizeof(req);
    req.hdr.nlmsg_type = RTM_GETROUTE;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.rt.rtm_family = AF_UNSPEC;

    ASSERT_GT(nl_send_request(s, &req, sizeof(req)), 0);

    std::vector<NlMessage> msgs;
    std::string err;
    ASSERT_TRUE(nl_read_dump(s, msgs, err)) << err;

    bool saw_default = false;
    for (auto &m : msgs) {
        if (m.hdr()->nlmsg_type != RTM_NEWROUTE) continue;
        auto *rt = reinterpret_cast<rtmsg *>(NLMSG_DATA(m.hdr()));
        if (rt->rtm_family == AF_INET && rt->rtm_dst_len == 0 &&
            rt->rtm_scope == RT_SCOPE_UNIVERSE) {
            saw_default = true;
        }
    }
    EXPECT_TRUE(saw_default) << "expected an IPv4 default route after gateway install";
    close(s);
}
