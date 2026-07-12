#pragma once

#include "test_mode.h"

#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>

namespace nfl_test {

// Build a sockaddr_in for 127.0.0.1:port (port in host byte order).
sockaddr_in loopback_v4(uint16_t port);

// Build a sockaddr_in6 for ::1:port (port in host byte order).
sockaddr_in6 loopback_v6(uint16_t port);

// Build a sockaddr_in for an arbitrary IPv4 host:port (host in dotted-quad).
sockaddr_in inet_addr_v4(const char *host, uint16_t port);

// Bind sock to 127.0.0.1:0 and return the assigned port (host byte order).
// On failure, returns 0 and the test should ASSERT_NE(0, port).
uint16_t bind_loopback_v4_ephemeral(int sock);

// Open a UDP/IPv4 socket and bind it to 127.0.0.1:0. Returns {fd, port}.
struct UdpSocket {
    int fd;
    uint16_t port;
};
UdpSocket make_bound_udp_v4();

// Base fixture for tests that exercise data flow or rely on test-module
// state. Resets per-process state (loopback packet queue, pending-accept
// counter) before and after each test (no-op in native mode). The TearDown
// matters under ASan: leftovers from the last test would otherwise show up
// as leaks at process exit.
class NetIOTest : public ::testing::Test {
protected:
    void SetUp() override;
    void TearDown() override;
};

}  // namespace nfl_test

// Test-module hooks. Defined by module-test.c in nfl mode. Native-mode stubs
// are provided in test_helpers.cpp so callers don't need #ifdefs.
extern "C" {
void module_test_reset_pending_packets(void);
// Make the next `n` calls to nfl_tcp_accept return success.
void module_test_set_pending_tcp_accepts(int n);
// When true, nfl_send reports NFL_CONN_CLOSED (peer gone) instead of accepting.
void module_test_set_send_closed(bool closed);
// When true, nfl_receive reports NFL_CONN_CLOSED (peer closed its end, EOF).
void module_test_set_recv_closed(bool closed);
}

// Assert a libc call returned -1 with the given errno. Intended for one-line
// negative-path checks.
//
//   EXPECT_LIBC_FAIL(bind(fd, &sa, 0), EINVAL);
//
#define EXPECT_LIBC_FAIL(expr, expected_errno) \
    do {                                       \
        errno = 0;                             \
        const auto _r = (expr);                \
        EXPECT_EQ(_r, -1) << #expr;            \
        EXPECT_EQ(errno, (expected_errno))     \
            << #expr << " errno=" << errno;    \
    } while (0)
