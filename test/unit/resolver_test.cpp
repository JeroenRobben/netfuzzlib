// getaddrinfo / getnameinfo / gethostbyname tests. The model resolves numeric
// literals, "localhost", and any address text matching a configured interface.
// Anything else, in nfl mode, sinks to a fixed bogus address (1.2.3.4 for
// v4, 2001:db8::1 for v6) so SUTs that hard-exit on resolver failure proceed
// into network code instead.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

using namespace nfl_test;

class ResolverTest : public NetIOTest {};

TEST_F(ResolverTest, GetaddrinfoNumericIpv4) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("127.0.0.1", "8080", &hints, &res));
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->ai_family, AF_INET);
    auto *sin = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    EXPECT_EQ(ntohs(sin->sin_port), 8080);
    EXPECT_EQ(ntohl(sin->sin_addr.s_addr), INADDR_LOOPBACK);
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoNumericIpv6) {
    addrinfo hints = {};
    hints.ai_family = AF_INET6;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("::1", "443", &hints, &res));
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->ai_family, AF_INET6);
    auto *sin6 = reinterpret_cast<sockaddr_in6 *>(res->ai_addr);
    EXPECT_EQ(ntohs(sin6->sin6_port), 443);
    EXPECT_EQ(0, memcmp(&sin6->sin6_addr, &in6addr_loopback, sizeof(in6addr_loopback)));
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoNullNodePassiveYieldsWildcard) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo(nullptr, "0", &hints, &res));
    ASSERT_NE(res, nullptr);
    auto *sin = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    EXPECT_EQ(sin->sin_addr.s_addr, htonl(INADDR_ANY));
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoNumericHintRejectsSymbolicHost) {
    // AI_NUMERICHOST forces the purely-numeric path: any non-numeric input
    // must fail without a DNS lookup. This makes the test deterministic on
    // hosts whose resolver might otherwise return SUCCESS for a search-domain
    // match.
    addrinfo hints = {};
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo *res = nullptr;
    int rc = getaddrinfo("definitely.not.a.host.invalid", nullptr, &hints, &res);
    EXPECT_EQ(rc, EAI_NONAME);
    if (res) freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoBogusHostNflResolvesToSink) {
    // Without AI_NUMERICHOST, nfl maps any unresolvable name to a fixed sink
    // address (1.2.3.4 for v4) so SUTs that hard-exit on resolver failure
    // proceed into network code. Native behaviour depends on the host's
    // resolver and may even succeed on misconfigured search domains, so this
    // test is nfl-only.
    SKIP_IF_NATIVE();
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("definitely.not.a.host.invalid", "443", &hints, &res));
    ASSERT_NE(res, nullptr);
    auto *sin = reinterpret_cast<sockaddr_in *>(res->ai_addr);
    char text[INET_ADDRSTRLEN] = {};
    inet_ntop(AF_INET, &sin->sin_addr, text, sizeof(text));
    EXPECT_STREQ(text, "1.2.3.4");
    EXPECT_EQ(ntohs(sin->sin_port), 443);
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoV4LiteralWithV6HintReturnsAddrFamily) {
    // glibc returns EAI_ADDRFAMILY when the literal's family doesn't match
    // the hint, and the model must do the same, otherwise SUTs that try a
    // dual-stack bind (pure-ftpd's standalone_server, …) get a synthesised
    // address and a fatal bind() failure. See src/core/resolver.c.
    addrinfo hints = {};
    hints.ai_family = AF_INET6;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    addrinfo *res = nullptr;
    int rc = getaddrinfo("127.0.0.1", "2121", &hints, &res);
    EXPECT_EQ(rc, EAI_ADDRFAMILY);
    EXPECT_EQ(res, nullptr);
    if (res) freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoV6LiteralWithV4HintReturnsAddrFamily) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    int rc = getaddrinfo("::1", "2121", &hints, &res);
    EXPECT_EQ(rc, EAI_ADDRFAMILY);
    EXPECT_EQ(res, nullptr);
    if (res) freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoNumericLiteralAfUnspecPicksLiteralFamily) {
    // AF_UNSPEC + numeric literal: return the family the literal actually is,
    // not both, and definitely not the synth fallback for the other family.
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("127.0.0.1", "2121", &hints, &res));
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->ai_family, AF_INET);
    EXPECT_EQ(res->ai_next, nullptr);
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoAiCanonnameOnHeadEntryNonNull) {
    // AI_CANONNAME callers (e.g. kamailio's log_init) read
    // info->ai_canonname unconditionally on success, and strdup(NULL) crashes.
    // Echo the input node back as canonname. Only the head entry gets one,
    // matching glibc. nfl-only: native getaddrinfo would return EAI_NONAME
    // for an unresolvable name, but nfl's sink-fallback synthesises a
    // success record we can attach the canonname to.
    SKIP_IF_NATIVE();
    addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_CANONNAME;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("some-hostname", "0", &hints, &res));
    ASSERT_NE(res, nullptr);
    ASSERT_NE(res->ai_canonname, nullptr);
    EXPECT_STREQ(res->ai_canonname, "some-hostname");
    for (addrinfo *p = res->ai_next; p; p = p->ai_next) {
        EXPECT_EQ(p->ai_canonname, nullptr);
    }
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetaddrinfoNoAiCanonnameLeavesNull) {
    addrinfo hints = {};
    hints.ai_family = AF_INET;
    hints.ai_flags = AI_NUMERICHOST;
    addrinfo *res = nullptr;
    ASSERT_EQ(0, getaddrinfo("127.0.0.1", "0", &hints, &res));
    ASSERT_NE(res, nullptr);
    EXPECT_EQ(res->ai_canonname, nullptr);
    freeaddrinfo(res);
}

TEST_F(ResolverTest, GetnameinfoNumericRoundTrip) {
    sockaddr_in sa = inet_addr_v4("127.0.0.1", 12345);
    char host[NI_MAXHOST] = {};
    char serv[NI_MAXSERV] = {};
    int rc = getnameinfo(reinterpret_cast<sockaddr *>(&sa), sizeof(sa),
                         host, sizeof(host), serv, sizeof(serv),
                         NI_NUMERICHOST | NI_NUMERICSERV);
    ASSERT_EQ(rc, 0);
    EXPECT_STREQ(host, "127.0.0.1");
    EXPECT_STREQ(serv, "12345");
}

TEST_F(ResolverTest, GethostbynameNumericIpv4) {
    hostent *he = gethostbyname("127.0.0.1");
    ASSERT_NE(he, nullptr);
    EXPECT_EQ(he->h_addrtype, AF_INET);
    EXPECT_EQ(he->h_length, static_cast<int>(sizeof(in_addr)));
    ASSERT_NE(he->h_addr_list, nullptr);
    ASSERT_NE(he->h_addr_list[0], nullptr);
    in_addr a;
    memcpy(&a, he->h_addr_list[0], sizeof(a));
    EXPECT_EQ(ntohl(a.s_addr), INADDR_LOOPBACK);
}
