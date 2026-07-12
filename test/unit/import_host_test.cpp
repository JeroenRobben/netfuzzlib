// Tests for nfl_import_host_network_devices(), the public API a module
// calls to mirror the host's network topology into the model.
//
// All cases are nfl-only: the function only exists in netfuzzlib, and each
// test runs in its own process (gtest_discover_tests registers one ctest
// entry per test), so calling import inside a test body is isolated and
// doesn't pollute the next test.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <dirent.h>
#include <cstring>
#include <set>
#include <string>

extern "C" {
void nfl_import_host_network_devices();
}

using namespace nfl_test;

namespace {

std::set<std::string> model_iface_names() {
    std::set<std::string> out;
    ifaddrs *ifap = nullptr;
    if (getifaddrs(&ifap) != 0 || !ifap) {
        return out;
    }
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (p->ifa_name) {
            out.insert(p->ifa_name);
        }
    }
    freeifaddrs(ifap);
    return out;
}

// What the host has, per /sys/class/net. Read directly (not via the model).
std::set<std::string> host_iface_names() {
    std::set<std::string> out;
    DIR *d = opendir("/sys/class/net");
    if (!d) {
        return out;
    }
    struct dirent *de;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] == '.') continue;
        out.insert(de->d_name);
    }
    closedir(d);
    return out;
}

}  // namespace

class ImportHostTest : public NetIOTest {};

TEST_F(ImportHostTest, BeforeImportModelHasOnlyConfiguredIfaces) {
    // Sanity check: in the default test module the model holds lo + eth0
    // before import. If this baseline drifts, subsequent assertions about
    // "what import added" become hard to reason about.
    SKIP_IF_NATIVE();
    auto before = model_iface_names();
    EXPECT_EQ(before.count("lo"), 1u);
    EXPECT_EQ(before.count("eth0"), 1u);
}

TEST_F(ImportHostTest, ImportDoesNotDuplicateLoopback) {
    // Both the model's auto-`lo` and the host's `lo` would otherwise produce
    // two entries. The dedup-by-name in import_l2_iface keeps it to one.
    SKIP_IF_NATIVE();
    nfl_import_host_network_devices();
    auto names_with_count = [&](const char *name) {
        ifaddrs *ifap = nullptr;
        if (getifaddrs(&ifap) != 0) return -1;
        int n = 0;
        for (ifaddrs *p = ifap; p; p = p->ifa_next) {
            if (p->ifa_name && strcmp(p->ifa_name, name) == 0 &&
                p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
                n++;
            }
        }
        freeifaddrs(ifap);
        return n;
    };
    // Exactly one IPv4 entry for "lo".
    EXPECT_EQ(names_with_count("lo"), 1);
}

TEST_F(ImportHostTest, ImportPreservesExistingModelInterface) {
    // Host import must not clobber an interface name already present in the
    // model. The default test module configures eth0 with 192.0.2.1, and if the
    // host also has an eth0 the dedup must keep the model's address, not the
    // host's.
    SKIP_IF_NATIVE();
    nfl_import_host_network_devices();
    bool found = false;
    ifaddrs *ifap = nullptr;
    ASSERT_EQ(0, getifaddrs(&ifap));
    for (ifaddrs *p = ifap; p; p = p->ifa_next) {
        if (p->ifa_name && strcmp(p->ifa_name, "eth0") == 0 &&
            p->ifa_addr && p->ifa_addr->sa_family == AF_INET) {
            const auto *sin = reinterpret_cast<const sockaddr_in *>(p->ifa_addr);
            char buf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            if (strcmp(buf, "192.0.2.1") == 0) {
                found = true;
                break;
            }
        }
    }
    freeifaddrs(ifap);
    EXPECT_TRUE(found) << "model's eth0=192.0.2.1 was lost during import";
}

TEST_F(ImportHostTest, ImportNamesAreSupersetOfBaseline) {
    // After import, the model's interface name set must contain everything
    // it had before. This is the contract of "additive import".
    SKIP_IF_NATIVE();
    auto before = model_iface_names();
    nfl_import_host_network_devices();
    auto after = model_iface_names();
    for (const auto &name : before) {
        EXPECT_EQ(after.count(name), 1u) << "lost iface " << name << " after import";
    }
}

TEST_F(ImportHostTest, ImportPicksUpHostOnlyInterfaces) {
    // Any name in /sys/class/net that *isn't* already in the model must
    // appear after import. Skips when there's nothing host-only to test
    // against (e.g., a minimal CI runner with only `lo`, already in model).
    SKIP_IF_NATIVE();
    auto before = model_iface_names();
    auto host = host_iface_names();
    std::set<std::string> host_only;
    for (const auto &name : host) {
        if (before.count(name) == 0) {
            host_only.insert(name);
        }
    }
    if (host_only.empty()) {
        GTEST_SKIP() << "host has no interfaces beyond what the model already has";
    }
    nfl_import_host_network_devices();
    auto after = model_iface_names();
    for (const auto &name : host_only) {
        EXPECT_EQ(after.count(name), 1u) << "host-only iface " << name << " not imported";
    }
}

TEST_F(ImportHostTest, ImportIsIdempotent) {
    // Calling import twice must yield the same model. This guards against
    // accidental double-add bugs in the dedup logic.
    SKIP_IF_NATIVE();
    nfl_import_host_network_devices();
    auto first = model_iface_names();
    nfl_import_host_network_devices();
    auto second = model_iface_names();
    EXPECT_EQ(first, second);
}
