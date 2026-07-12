// Tests for getifaddrs(3) / if_nametoindex / if_indextoname.
// Both modes have a "lo" loopback (host kernel always, nfl auto-adds in init).

#include "test_helpers.h"

#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netpacket/packet.h>
#include <sys/socket.h>
#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

using namespace nfl_test;

namespace {

std::vector<std::string> collect_interface_names(ifaddrs *ifap) {
    std::vector<std::string> names;
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (p->ifa_name) {
            names.push_back(p->ifa_name);
        }
    }
    return names;
}

bool any_with_family(ifaddrs *ifap, int family) {
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family == family) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(GetifaddrsTest, ReturnsZeroAndNonNullList) {
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    ASSERT_NE(ifap, nullptr);
    freeifaddrs(ifap);
}

TEST(GetifaddrsTest, LoopbackIsPresent) {
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    const auto names = collect_interface_names(ifap);
    EXPECT_NE(std::find(names.begin(), names.end(), "lo"), names.end())
        << "loopback interface 'lo' missing from getifaddrs result";
    freeifaddrs(ifap);
}

TEST(GetifaddrsTest, EveryEntryHasName) {
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        EXPECT_NE(p->ifa_name, nullptr);
        if (p->ifa_name) {
            EXPECT_GT(strlen(p->ifa_name), 0u);
        }
    }
    freeifaddrs(ifap);
}

TEST(GetifaddrsTest, Ipv4EntryHasNonNullNetmask) {
    // Apps regularly dereference ifa_netmask without a NULL check, so an IPv4
    // entry must always carry one.
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));

    bool saw_v4 = false;
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
            saw_v4 = true;
            EXPECT_NE(p->ifa_netmask, nullptr) << "iface " << p->ifa_name;
        }
    }
    EXPECT_TRUE(saw_v4) << "expected at least one IPv4 entry (loopback 127/8)";
    freeifaddrs(ifap);
}

TEST(GetifaddrsTest, AfPacketEntryEmitted) {
    // glibc and the model both emit an AF_PACKET (link-layer) entry per
    // interface. Check at least one is present.
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    EXPECT_TRUE(any_with_family(ifap, AF_PACKET));
    freeifaddrs(ifap);
}

TEST(IfIndexTest, IfNametoindexLoopbackIsNonZero) {
    EXPECT_NE(if_nametoindex("lo"), 0u);
}

TEST(IfIndexTest, IfNametoindexUnknownReturnsZero) {
    // POSIX/Linux: failure returns 0, not -1.
    errno = 0;
    EXPECT_EQ(0u, if_nametoindex("definitely-not-an-iface-xyz"));
    EXPECT_EQ(errno, ENODEV);
}

TEST(IfIndexTest, IfIndextonameRoundTripsLo) {
    const unsigned int idx = if_nametoindex("lo");
    ASSERT_NE(idx, 0u);
    char name[IF_NAMESIZE] = {};
    EXPECT_EQ(if_indextoname(idx, name), name);
    EXPECT_STREQ(name, "lo");
}

TEST(IfIndexTest, IfIndextonameUnknownReturnsNull) {
    char name[IF_NAMESIZE] = {};
    errno = 0;
    EXPECT_EQ(if_indextoname(99999, name), nullptr);
    EXPECT_NE(errno, 0);
}

TEST(IfIndexTest, IfNameindexEnumeratesLoopback) {
    // `if_nameindex` is both a struct tag and a function, so qualify the type
    // explicitly so the parser doesn't pick the wrong one.
    struct if_nameindex *list = if_nameindex();
    ASSERT_NE(list, nullptr);
    bool saw_lo = false;
    bool saw_sentinel = false;
    for (struct if_nameindex *p = list; ; p++) {
        if (p->if_index == 0 && p->if_name == nullptr) {
            saw_sentinel = true;
            break;
        }
        ASSERT_NE(p->if_name, nullptr);
        EXPECT_NE(p->if_index, 0u);
        if (strcmp(p->if_name, "lo") == 0) {
            saw_lo = true;
        }
    }
    EXPECT_TRUE(saw_sentinel) << "list must end in {0, NULL} sentinel";
    EXPECT_TRUE(saw_lo) << "loopback iface absent from if_nameindex result";
    if_freenameindex(list);
}

TEST(GetifaddrsTest, FamilyIsAlwaysOneOfKnown) {
    // Spec: ifa_addr->sa_family ∈ {AF_INET, AF_INET6, AF_PACKET}.
    // Anything else means broken model output or memory corruption.
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (!p->ifa_addr) {
            continue;
        }
        const int fam = p->ifa_addr->sa_family;
        EXPECT_TRUE(fam == AF_INET || fam == AF_INET6 || fam == AF_PACKET)
            << "iface " << p->ifa_name << " has unexpected family " << fam;
    }
    freeifaddrs(ifap);
}
