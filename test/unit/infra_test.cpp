// Built-in self-test for the test framework itself: confirms the two binaries
// really exercise different code paths. If the nfl interceptor library stops
// being linked into tests_nfl, these tests fail.

#include "test_helpers.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace nfl_test;

// netfuzzlib's reserved socket fd range. See src/core/network_types.h.
static constexpr int kNflFdStart = 70;
static constexpr int kNflFdMax = 1024;

TEST(InfraTest, NewSocketFdIsInNflRangeWhenNflLinked) {
    SKIP_IF_NATIVE();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    EXPECT_GE(s, kNflFdStart) << "socket() returned " << s
        << ", netfuzzlib interceptor is not active";
    EXPECT_LE(s, kNflFdMax);
    close(s);
}

TEST(InfraTest, NewSocketFdIsKernelAssignedInNativeMode) {
    SKIP_IF_NFL();
    const int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    // The real kernel hands out the lowest free fd. In a small test binary
    // that's single- or low-double-digit, well below netfuzzlib's reserved
    // range. If this hits the nfl range, libnfl leaked into the build.
    EXPECT_LT(s, kNflFdStart) << "native socket fd " << s
        << " is in netfuzzlib's reserved range, interceptor leaked into native build";
    close(s);
}
