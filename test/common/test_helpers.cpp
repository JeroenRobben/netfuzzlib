#include "test_helpers.h"

#include <arpa/inet.h>
#include <cstring>

namespace nfl_test {

sockaddr_in loopback_v4(uint16_t port) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return sa;
}

sockaddr_in6 loopback_v6(uint16_t port) {
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_port = htons(port);
    sa.sin6_addr = in6addr_loopback;
    return sa;
}

sockaddr_in inet_addr_v4(const char *host, uint16_t port) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    inet_pton(AF_INET, host, &sa.sin_addr);
    return sa;
}

uint16_t bind_loopback_v4_ephemeral(int sock) {
    sockaddr_in sa = loopback_v4(0);
    if (bind(sock, reinterpret_cast<sockaddr *>(&sa), sizeof(sa)) != 0) {
        return 0;
    }
    sockaddr_in bound{};
    socklen_t len = sizeof(bound);
    if (getsockname(sock, reinterpret_cast<sockaddr *>(&bound), &len) != 0) {
        return 0;
    }
    return ntohs(bound.sin_port);
}

UdpSocket make_bound_udp_v4() {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        return {-1, 0};
    }
    const uint16_t port = bind_loopback_v4_ephemeral(fd);
    if (port == 0) {
        close(fd);
        return {-1, 0};
    }
    return {fd, port};
}

void NetIOTest::SetUp() {
    module_test_reset_pending_packets();
    module_test_set_pending_tcp_accepts(0);
    module_test_set_send_closed(false);
    module_test_set_recv_closed(false);
}

void NetIOTest::TearDown() {
    module_test_reset_pending_packets();
    module_test_set_pending_tcp_accepts(0);
    module_test_set_send_closed(false);
    module_test_set_recv_closed(false);
}

}  // namespace nfl_test

#if defined(NFL_TEST_NATIVE_MODE)
// In native mode neither the test module nor libnfl is linked. Provide
// no-op stubs so callers don't need #ifdefs.
extern "C" {
void module_test_reset_pending_packets(void) {}
void module_test_set_pending_tcp_accepts(int n) { (void)n; }
void module_test_set_send_closed(bool closed) { (void)closed; }
void module_test_set_recv_closed(bool closed) { (void)closed; }
void nfl_reserve_fd_pool(int count) { (void)count; }
}
#endif
