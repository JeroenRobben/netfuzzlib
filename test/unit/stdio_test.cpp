// stdio interceptor + nfl helpers covering fdopen on a socket fd, fileno round-trip,
// fread/fwrite/fgets/fgetc/fprintf/fclose dispatching through the recvfrom_nfl /
// sendto_nfl path. Covers src/interceptors/stdio.c and src/core/stdio.c.
//
// Most cases are nfl-only: the SUT cast (FILE*)(long)fd sentinel is an nfl
// implementation detail, and the routing through fread_nfl/fwrite_nfl only
// exists in nfl mode.

#include "test_helpers.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <cstring>

using namespace nfl_test;

class StdioTest : public NetIOTest {};

// fileno on a real libc FILE* must still work, the interceptor only diverts for
// the nfl sentinel.
TEST_F(StdioTest, FilenoOnRealStreamPassesThrough) {
    EXPECT_EQ(2, fileno(stderr));
}

// fflush(NULL) flushes every open output stream. We forward to native.
TEST_F(StdioTest, FflushNullForwardsToNative) {
    EXPECT_EQ(0, fflush(nullptr));
}

TEST_F(StdioTest, FdopenOnNflSocketReturnsCastedFd) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    ASSERT_GE(u.fd, 0);
    FILE *f = fdopen(u.fd, "r+");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(u.fd, fileno(f));
    EXPECT_EQ(0, fclose(f));  // closes underlying fd
}

TEST_F(StdioTest, FwriteToNflStreamGoesThroughSendPath) {
    // Open a UDP receiver, then do fdopen+fwrite on a connected sender. The
    // bytes should land in the receiver's queue.
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();

    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    const char msg[] = "hello";
    EXPECT_EQ(static_cast<size_t>(5), fwrite(msg, 1, 5, f));

    char buf[16] = {};
    EXPECT_EQ(static_cast<ssize_t>(5),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "hello", 5));

    fclose(f);
    close(receiver.fd);
}

// An inetd-model daemon dup2's its accepted connection onto stdin/stdout/stderr
// and then does control I/O through the pre-existing libc FILE* (bftpd's banner
// is fprintf(stderr, ...)). Those are genuine FILE* pointers, not our
// (FILE*)(long)fd sentinel, so the stdio interceptor must still route them to
// the model whenever their backing fd is a modelled socket. Otherwise the write
// escapes to the /dev/null the fd number is parked on and the peer never sees it.
TEST_F(StdioTest, RealFileStreamOverDup2dModelledFdRoutesToModel) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();

    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    // A genuine libc FILE*, left unbuffered so a write reaches the fd at once.
    FILE *f = fopen("/dev/null", "w");
    ASSERT_NE(nullptr, f);
    ASSERT_EQ(0, setvbuf(f, nullptr, _IONBF, 0));
    int rfd = fileno(f);
    ASSERT_GE(rfd, 0);

    // Park the modelled connection on the real FILE*'s fd, the way a daemon does
    // with dup2(conn, fileno(stderr)).
    ASSERT_EQ(rfd, dup2(sender, rfd));

    const char msg[] = "hello";
    EXPECT_EQ(static_cast<size_t>(5), fwrite(msg, 1, 5, f));

    char buf[16] = {};
    EXPECT_EQ(static_cast<ssize_t>(5),
              recv(receiver.fd, buf, sizeof(buf), MSG_DONTWAIT));
    EXPECT_EQ(0, memcmp(buf, "hello", 5));

    fclose(f);
    close(sender);
    close(receiver.fd);
}

TEST_F(StdioTest, FreadFromNflStreamPullsViaRecv) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    const char msg[] = "world";
    ASSERT_EQ(static_cast<ssize_t>(5),
              sendto(sender, msg, 5, 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    char buf[16] = {};
    EXPECT_EQ(static_cast<size_t>(5), fread(buf, 1, 5, f));
    EXPECT_EQ(0, memcmp(buf, "world", 5));

    fclose(f);
    close(sender);
}

TEST_F(StdioTest, FgetcOnNflStreamReadsOneByte) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    char one = 'Q';
    ASSERT_EQ(1, sendto(sender, &one, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ('Q', fgetc(f));

    fclose(f);
    close(sender);
}

TEST_F(StdioTest, GetcDelegatesToFgetc) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    char one = 'Z';
    ASSERT_EQ(1, sendto(sender, &one, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ('Z', getc(f));
    fclose(f);
    close(sender);
}

TEST_F(StdioTest, FgetsReadsUntilNewlineAcrossDatagrams) {
    // fgets_nfl reads one byte at a time via fgetc_nfl. Each fgetc consumes a
    // datagram (Linux UDP: read of 1 byte truncates the datagram). To produce
    // "X\n" we must inject two single-byte datagrams.
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);

    const char x = 'X';
    const char nl = '\n';
    ASSERT_EQ(1, sendto(sender, &x, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    ASSERT_EQ(1, sendto(sender, &nl, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    char buf[16] = {};
    EXPECT_EQ(buf, fgets(buf, sizeof(buf), f));
    EXPECT_STREQ("X\n", buf);

    fclose(f);
    close(sender);
}

TEST_F(StdioTest, FprintfFormatsAndSends) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(4, fprintf(f, "%s=%d", "n", 42));

    char buf[16] = {};
    EXPECT_EQ(static_cast<ssize_t>(4),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("n=42", buf);

    fclose(f);
    close(receiver.fd);
}

TEST_F(StdioTest, FflushOnNflStreamIsNoop) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(0, fflush(f));
    fclose(f);
}

TEST_F(StdioTest, FcloseClosesUnderlyingNflFd) {
    SKIP_IF_NATIVE();
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(s, 0);
    FILE *f = fdopen(s, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(0, fclose(f));
    // After fclose, sends on the underlying fd must fail.
    char buf[1] = {0};
    EXPECT_LIBC_FAIL(send(s, buf, 1, 0), EBADF);
}

// ---- crash-hazard interceptors: feof/ferror/clearerr ----------------------
// Without the new interceptors these would deref our (FILE*)(long)fd
// sentinel through glibc's _IO_FILE accessors and segfault.

TEST_F(StdioTest, FeofOnNflStreamReturnsZero) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(0, feof(f));  // model doesn't track EOF, safe default is "no"
    fclose(f);
}

TEST_F(StdioTest, FerrorOnNflStreamReturnsZero) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(0, ferror(f));
    fclose(f);
}

TEST_F(StdioTest, ClearerrOnNflStreamIsSafeNoop) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);
    clearerr(f);  // must not crash
    EXPECT_EQ(0, ferror(f));
    fclose(f);
}

// ---- crash-hazard interceptors: fseek/ftell/rewind ------------------------

TEST_F(StdioTest, FseekOnNflStreamReturnsEspipe) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r+");
    ASSERT_NE(nullptr, f);
    errno = 0;
    EXPECT_EQ(-1, fseek(f, 0, SEEK_SET));
    EXPECT_EQ(ESPIPE, errno);
    fclose(f);
}

TEST_F(StdioTest, FtellOnNflStreamReturnsEspipe) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r+");
    ASSERT_NE(nullptr, f);
    errno = 0;
    EXPECT_EQ(-1L, ftell(f));
    EXPECT_EQ(ESPIPE, errno);
    fclose(f);
}

TEST_F(StdioTest, RewindOnNflStreamIsSafeNoop) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r+");
    ASSERT_NE(nullptr, f);
    rewind(f);  // must not crash, rewind is void so no return to assert
    fclose(f);
}

// ---- crash-hazard interceptors: setbuf/setvbuf ----------------------------

TEST_F(StdioTest, SetbufOnNflStreamIsSafeNoop) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "w");
    ASSERT_NE(nullptr, f);
    setbuf(f, nullptr);  // request unbuffered, must not crash
    fclose(f);
}

TEST_F(StdioTest, SetvbufOnNflStreamReturnsZero) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "w");
    ASSERT_NE(nullptr, f);
    char buf[64];
    EXPECT_EQ(0, setvbuf(f, buf, _IOFBF, sizeof(buf)));
    fclose(f);
}

// ---- FORTIFY_SOURCE chk-variant shims -------------------------------------

extern "C" {
char *__fgets_chk(char *s, size_t size, int n, FILE *stream);
size_t __fread_chk(void *ptr, size_t ptrlen, size_t size, size_t n, FILE *stream);
int __fprintf_chk(FILE *stream, int flag, const char *format, ...);
}

TEST_F(StdioTest, FreadChkRoutesThroughNflStream) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    const char msg[] = "world";
    ASSERT_EQ(static_cast<ssize_t>(5),
              sendto(sender, msg, 5, 0, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);
    char buf[16] = {};
    EXPECT_EQ(static_cast<size_t>(5), __fread_chk(buf, sizeof(buf), 1, 5, f));
    EXPECT_EQ(0, memcmp(buf, "world", 5));
    fclose(f);
    close(sender);
}

TEST_F(StdioTest, FgetsChkRoutesThroughNflStream) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    const char x = 'X';
    const char nl = '\n';
    ASSERT_EQ(1, sendto(sender, &x, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    ASSERT_EQ(1, sendto(sender, &nl, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);
    char buf[16] = {};
    EXPECT_EQ(buf, __fgets_chk(buf, sizeof(buf), sizeof(buf), f));
    EXPECT_STREQ("X\n", buf);
    fclose(f);
    close(sender);
}

TEST_F(StdioTest, FprintfChkRoutesThroughNflStream) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(4, __fprintf_chk(f, 1 /* FORTIFY level placeholder */, "%s=%d", "n", 42));

    char buf[16] = {};
    EXPECT_EQ(static_cast<ssize_t>(4),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_STREQ("n=42", buf);
    fclose(f);
    close(receiver.fd);
}

// ---- output coverage: fputs / fputc / putc / puts -------------------------

TEST_F(StdioTest, FputsWritesStringWithoutNewline) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_GE(fputs("hello", f), 0);

    char buf[16] = {};
    EXPECT_EQ(static_cast<ssize_t>(5),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_EQ(0, memcmp(buf, "hello", 5));
    fclose(f);
    close(receiver.fd);
}

TEST_F(StdioTest, FputcWritesSingleByte) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ('Q', fputc('Q', f));

    char buf[2] = {};
    EXPECT_EQ(static_cast<ssize_t>(1),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_EQ('Q', buf[0]);
    fclose(f);
    close(receiver.fd);
}

TEST_F(StdioTest, PutcDelegatesToFputc) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    ASSERT_EQ(0, connect(sender, reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    FILE *f = fdopen(sender, "w");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ('Z', putc('Z', f));

    char buf[2] = {};
    EXPECT_EQ(static_cast<ssize_t>(1),
              recv(receiver.fd, buf, sizeof(buf), 0));
    EXPECT_EQ('Z', buf[0]);
    fclose(f);
    close(receiver.fd);
}

// ---- input coverage: ungetc -----------------------------------------------

TEST_F(StdioTest, UngetcThenFgetcReturnsPushedByte) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    const char one = 'A';
    ASSERT_EQ(1, sendto(sender, &one, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    EXPECT_EQ('A', fgetc(f));
    EXPECT_EQ('A', ungetc('A', f));
    EXPECT_EQ('A', fgetc(f));  // re-reads from pushback
    fclose(f);
    close(sender);
}

TEST_F(StdioTest, UngetcSecondPushReturnsEofWithoutDisturbingFirst) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);

    EXPECT_EQ('X', ungetc('X', f));
    EXPECT_EQ(EOF, ungetc('Y', f));  // second push must be refused
    EXPECT_EQ('X', fgetc(f));        // first push is still live
    fclose(f);
}

TEST_F(StdioTest, UngetcOfEofIsNoop) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);
    EXPECT_EQ(EOF, ungetc(EOF, f));  // C99: ungetc(EOF, ...) is a no-op
    fclose(f);
}

// ---- input coverage: getline / getdelim -----------------------------------
//
// The nfl path sees one datagram per fgetc (UDP read of 1 byte truncates the
// rest). To produce a multi-byte line we send each byte as its own datagram.

TEST_F(StdioTest, GetlineReadsLineUpToNewline) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    for (char c : std::string("hi\n")) {
        ASSERT_EQ(1, sendto(sender, &c, 1, 0,
                            reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    }

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    char *line = nullptr;
    size_t n = 0;
    const ssize_t got = getline(&line, &n, f);
    EXPECT_EQ(static_cast<ssize_t>(3), got);
    ASSERT_NE(nullptr, line);
    EXPECT_STREQ("hi\n", line);
    EXPECT_GE(n, static_cast<size_t>(4));  // buffer accommodates string + NUL
    free(line);

    fclose(f);
    close(sender);
}

TEST_F(StdioTest, GetdelimReadsToCustomDelimiter) {
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    for (char c : std::string("foo;rest")) {
        ASSERT_EQ(1, sendto(sender, &c, 1, 0,
                            reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));
    }

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    char *chunk = nullptr;
    size_t n = 0;
    const ssize_t got = getdelim(&chunk, &n, ';', f);
    EXPECT_EQ(static_cast<ssize_t>(4), got);  // "foo;" inclusive
    EXPECT_STREQ("foo;", chunk);
    free(chunk);

    fclose(f);
    close(sender);
}

TEST_F(StdioTest, GetlineWithNullBufAllocates) {
    // Passing *lineptr=NULL and *n=0 is the canonical first-call shape, so
    // getline must allocate a buffer rather than try to write into NULL.
    SKIP_IF_NATIVE();
    auto receiver = make_bound_udp_v4();
    int sender = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(sender, 0);
    sockaddr_in dst = loopback_v4(receiver.port);
    const char nl = '\n';
    ASSERT_EQ(1, sendto(sender, &nl, 1, 0,
                        reinterpret_cast<sockaddr *>(&dst), sizeof(dst)));

    FILE *f = fdopen(receiver.fd, "r");
    ASSERT_NE(nullptr, f);

    char *line = nullptr;
    size_t n = 0;
    const ssize_t got = getline(&line, &n, f);
    EXPECT_EQ(static_cast<ssize_t>(1), got);
    ASSERT_NE(nullptr, line);
    EXPECT_STREQ("\n", line);
    free(line);

    fclose(f);
    close(sender);
}

// ---- formatted-input: fscanf / vfscanf abort on nfl streams --------------
//
// Real Linux fscanf on a socket would succeed. Silently returning EOF would
// turn a fuzz finding into a false negative. The interceptor nfl_die's
// instead so the operator sees a loud, actionable abort.

TEST_F(StdioTest, FscanfOnNflStreamAborts) {
    SKIP_IF_NATIVE();
    auto u = make_bound_udp_v4();
    FILE *f = fdopen(u.fd, "r");
    ASSERT_NE(nullptr, f);
    int v = 0;
    EXPECT_DEATH(fscanf(f, "%d", &v), "vfscanf is not modeled");
    /* Process is gone after EXPECT_DEATH's child exits, no fclose needed. */
}
