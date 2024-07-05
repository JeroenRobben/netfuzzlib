#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include "netfuzzlib/api.h"
#include "netfuzzlib/util.h"

socklen_t get_socket_domain_addrlen(int domain) {
    switch (domain) {
    case (AF_INET):
        return sizeof(struct sockaddr_in);
    case (AF_INET6):
        return sizeof(struct sockaddr_in6);
    case (AF_NETLINK):
        return sizeof(struct sockaddr_nl);
    default:
        nfl_exit_log(1, "get_socket_domain_addrlen on invalid socket domain");
    }
}

bool addr_is_zero_address(const nfl_addr_t *addr) {
    switch (addr->s.sa_family) {
    case (AF_INET):
        return addr->s4.sin_addr.s_addr == INADDR_ANY;
    case (AF_INET6):
        return IN6_IS_ADDR_UNSPECIFIED(&addr->s6.sin6_addr);
    }
    __builtin_unreachable();
}

bool ip_endpoints_match(const nfl_addr_t *addr1, const nfl_addr_t *addr2) {
    if (addr1->s.sa_family != addr2->s.sa_family)
        return false;
    bool match_by_wildcard_address = addr_is_zero_address(addr1) || addr_is_zero_address(addr2);
    switch (addr1->s.sa_family) {
    case (AF_INET): {
        if (addr1->s4.sin_port != addr2->s4.sin_port && addr1->s4.sin_port != 0 && addr2->s4.sin_port != 0)
            return false;
        return match_by_wildcard_address || (addr1->s4.sin_addr.s_addr == addr2->s4.sin_addr.s_addr);
    }
    case (AF_INET6): {
        if (addr1->s6.sin6_port != addr2->s6.sin6_port && addr1->s6.sin6_port != 0 && addr2->s6.sin6_port != 0)
            return false;
        return match_by_wildcard_address || (memcmp(&addr1->s6.sin6_addr, &addr2->s6.sin6_addr, sizeof(struct in6_addr)) == 0);
    }
    }
    __builtin_unreachable();
}

ssize_t iov_count_bytes(struct iovec *iov, size_t iovlen) {
    ssize_t total = 0;
    for (size_t i = 0; i < iovlen; i++) {
        total += (ssize_t)iov[i].iov_len;
    }
    return total;
}

uint16_t nfl_addr_get_port_network_byte_order(nfl_addr_t *addr) {
    switch (addr->s.sa_family) {
    case (AF_INET):
        return addr->s4.sin_port;
    case (AF_INET6):
        return addr->s6.sin6_port;
    }
    __builtin_unreachable();
}