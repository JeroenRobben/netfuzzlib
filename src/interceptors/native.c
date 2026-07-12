/* Direct syscalls for everything that maps 1:1 to the kernel ABI.
 * errno is set on -1 by syscall() exactly like the libc
 * wrappers. Stdio (FILE*) functions still go through dlsym to glibc */

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <netfuzzlib/api.h>
#include "native.h"

int socket_native(const int domain, const int type, const int protocol) {
    return (int)syscall(SYS_socket, domain, type, protocol);
}

int bind_native(const int fd, const struct sockaddr *addr, const socklen_t len) {
    return (int)syscall(SYS_bind, fd, addr, len);
}

int connect_native(const int fd, const struct sockaddr *addr, const socklen_t addrlen) {
    return (int)syscall(SYS_connect, fd, addr, addrlen);
}

int accept_native(const int fd, struct sockaddr *addr, socklen_t *len) {
    return (int)syscall(SYS_accept, fd, addr, len);
}

int accept4_native(const int fd, struct sockaddr *addr, socklen_t *len, const int flags) {
    return (int)syscall(SYS_accept4, fd, addr, len, flags);
}

int getpeername_native(const int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return (int)syscall(SYS_getpeername, fd, addr, addrlen);
}

int getsockname_native(const int fd, struct sockaddr *addr, socklen_t *addrlen) {
    return (int)syscall(SYS_getsockname, fd, addr, addrlen);
}

int getsockopt_native(const int fd, const int level, const int option_name, void *option_value, socklen_t *option_len) {
    return (int)syscall(SYS_getsockopt, fd, level, option_name, option_value, option_len);
}

int setsockopt_native(const int fd, const int level, const int option_name, const void *option_value, const socklen_t option_len) {
    return (int)syscall(SYS_setsockopt, fd, level, option_name, option_value, option_len);
}

int listen_native(const int fd, const int backlog) {
    return (int)syscall(SYS_listen, fd, backlog);
}

int close_native(const int fd) {
    return (int)syscall(SYS_close, fd);
}

int shutdown_native(const int fd, const int how) {
    return (int)syscall(SYS_shutdown, fd, how);
}

int select_native(const int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
#ifdef SYS_select
    return (int)syscall(SYS_select, nfds, readfds, writefds, exceptfds, timeout);
#else
    struct timespec ts;
    struct timespec *ts_arg = NULL;
    if (timeout) {
        ts.tv_sec = timeout->tv_sec;
        ts.tv_nsec = timeout->tv_usec * 1000;
        ts_arg = &ts;
    }
    return (int)syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, ts_arg, NULL);
#endif
}

int pselect_native(const int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    /* Kernel pselect6 takes a packed (sigset*, size) pair as its 6th arg. */
    const struct {
        const sigset_t *ss;
        size_t ss_len;
    } sigmask_arg = { sigmask, sigmask ? sizeof(sigset_t) : 0 };

    /* POSIX says pselect doesn't modify *timeout, but kernel pselect6 may.
     * Pass a private copy to preserve POSIX semantics. */
    struct timespec ts_local;
    struct timespec *ts_arg = NULL;
    if (timeout) {
        ts_local = *timeout;
        ts_arg = &ts_local;
    }
    return (int)syscall(SYS_pselect6, nfds, readfds, writefds, exceptfds, ts_arg, &sigmask_arg);
}

int poll_native(struct pollfd *fds, const nfds_t nfds, const int timeout) {
#ifdef SYS_poll
    return (int)syscall(SYS_poll, fds, nfds, timeout);
#else
    struct timespec ts;
    struct timespec *ts_arg = NULL;
    if (timeout >= 0) {
        ts.tv_sec = timeout / 1000;
        ts.tv_nsec = (long)(timeout % 1000) * 1000000L;
        ts_arg = &ts;
    }
    return (int)syscall(SYS_ppoll, fds, nfds, ts_arg, NULL, sizeof(sigset_t));
#endif
}

int ppoll_native(struct pollfd *fds, const nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    /* Kernel ppoll modifies *timeout, POSIX ppoll doesn't. Copy to preserve. */
    struct timespec ts_local;
    struct timespec *ts_arg = NULL;
    if (timeout_ts) {
        ts_local = *timeout_ts;
        ts_arg = &ts_local;
    }
    return (int)syscall(SYS_ppoll, fds, nfds, ts_arg, sigmask, sigmask ? sizeof(sigset_t) : 0);
}

int ioctl_native(const int fd, const unsigned long request, void *argp) {
    return (int)syscall(SYS_ioctl, fd, request, argp);
}

int pipe_native(int filedes[2]) {
    return (int)syscall(SYS_pipe2, filedes, 0);
}

ssize_t read_native(const int fd, void *buf, const size_t count) {
    return syscall(SYS_read, fd, buf, count);
}

ssize_t readv_native(const int fd, const struct iovec *iov, const int iovcnt) {
    return syscall(SYS_readv, fd, iov, iovcnt);
}

ssize_t pread_native(const int fd, void *buf, const size_t count, const off_t offset) {
    return syscall(SYS_pread64, fd, buf, count, offset);
}

ssize_t recvfrom_native(const int fd, void *buf, const size_t len, const int flags, struct sockaddr *remote_addr, socklen_t *addrlen) {
    return syscall(SYS_recvfrom, fd, buf, len, flags, remote_addr, addrlen);
}

ssize_t recvmsg_native(const int fd, struct msghdr *msg, const int flags) {
    return syscall(SYS_recvmsg, fd, msg, flags);
}

int recvmmsg_native(const int fd, void *msgvec, const unsigned int vlen, const int flags, struct timespec *timeout) {
    return (int)syscall(SYS_recvmmsg, fd, msgvec, vlen, flags, timeout);
}

int epoll_create_native(const int size) {
    /* SYS_epoll_create has been a no-op alias for epoll_create1(0) since
     * Linux 2.6.27. The size arg is kept only for ABI compatibility. */
    return (int)syscall(SYS_epoll_create1, 0);
}

int epoll_create1_native(const int flags) {
    return (int)syscall(SYS_epoll_create1, flags);
}

int epoll_ctl_native(const int epfd, const int op, const int fd, void *event) {
    return (int)syscall(SYS_epoll_ctl, epfd, op, fd, event);
}

int epoll_wait_native(const int epfd, void *events, const int maxevents, const int timeout) {
    return (int)syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, NULL, 0);
}

int epoll_pwait_native(const int epfd, void *events, const int maxevents,
                       const int timeout, const sigset_t *sigmask) {
    return (int)syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, sigmask, sizeof(sigset_t));
}

int epoll_pwait2_native(const int epfd, void *events, const int maxevents,
                        const struct timespec *timeout, const sigset_t *sigmask) {
#ifdef SYS_epoll_pwait2
    return (int)syscall(SYS_epoll_pwait2, epfd, events, maxevents, timeout, sigmask, sizeof(sigset_t));
#else
    /* Older kernels: degrade to ms-resolution pwait. */
    int timeout_ms = -1;
    if (timeout) {
        timeout_ms = (int)(timeout->tv_sec * 1000 + timeout->tv_nsec / 1000000);
    }
    return epoll_pwait_native(epfd, events, maxevents, timeout_ms, sigmask);
#endif
}

ssize_t write_native(const int fd, void const *buf, const size_t len) {
    return syscall(SYS_write, fd, buf, len);
}

ssize_t writev_native(const int fd, const struct iovec *iov, const int iovcnt) {
    return syscall(SYS_writev, fd, iov, iovcnt);
}

int sendmmsg_native(const int fd, void *msgvec, const unsigned int vlen, const int flags) {
    return (int)syscall(SYS_sendmmsg, fd, msgvec, vlen, flags);
}

ssize_t sendfile_native(const int out_fd, const int in_fd, off_t *offset, const size_t count) {
    return syscall(SYS_sendfile, out_fd, in_fd, offset, count);
}

ssize_t sendto_native(const int fd, const void *buf, const size_t len, const int flags, const struct sockaddr *remote_addr, const socklen_t addrlen) {
    return syscall(SYS_sendto, fd, buf, len, flags, remote_addr, addrlen);
}

ssize_t sendmsg_native(const int fd, const struct msghdr *msg, const int flags) {
    return syscall(SYS_sendmsg, fd, msg, flags);
}

int fcntl_native(const int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    const long arg = va_arg(ap, long);
    va_end(ap);
    return (int)syscall(SYS_fcntl, fd, cmd, arg);
}

int fcntl64_native(const int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    const long arg = va_arg(ap, long);
    va_end(ap);
#ifdef SYS_fcntl64
    return (int)syscall(SYS_fcntl64, fd, cmd, arg);
#else
    return (int)syscall(SYS_fcntl, fd, cmd, arg);
#endif
}

int dup_native(const int oldfd) {
    return (int)syscall(SYS_dup, oldfd);
}

int dup2_native(const int oldfd, const int newfd) {
#ifdef SYS_dup2
    return (int)syscall(SYS_dup2, oldfd, newfd);
#else
    return (int)syscall(SYS_dup3, oldfd, newfd, 0);
#endif
}

int dup3_native(const int oldfd, const int newfd, const int flags) {
    return (int)syscall(SYS_dup3, oldfd, newfd, flags);
}

void closefrom_native(const int low_fd) {
    /* Linux has no closefrom syscall, close_range(low, ~0, 0) is the equivalent. */
    (void)syscall(SYS_close_range, (unsigned int)low_fd, ~0u, 0u);
}

int close_range_native(const unsigned int low_fd, const unsigned int max_fd, const unsigned int flags) {
    return (int)syscall(SYS_close_range, low_fd, max_fd, flags);
}

/* Stdio wrappers. No single-syscall equivalent, must dlsym. */

int fileno_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fileno");
    }
    return fn(stream);
}

FILE *fdopen_native(const int fd, const char *mode) {
    static FILE *(*fn)(int, const char *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fdopen");
    }
    return fn(fd, mode);
}

char *fgets_native(char *s, const int size, FILE *stream) {
    static char *(*fn)(char *, int, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fgets");
    }
    return fn(s, size, stream);
}

int fgetc_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fgetc");
    }
    return fn(stream);
}

size_t fread_native(void *ptr, const size_t size, const size_t nmemb, FILE *stream) {
    static size_t (*fn)(void *, size_t, size_t, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fread");
    }
    return fn(ptr, size, nmemb, stream);
}

size_t fwrite_native(const void *ptr, const size_t size, const size_t nmemb, FILE *stream) {
    static size_t (*fn)(const void *, size_t, size_t, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fwrite");
    }
    return fn(ptr, size, nmemb, stream);
}

int fclose_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fclose");
    }
    return fn(stream);
}

int fflush_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fflush");
    }
    return fn(stream);
}

int vfprintf_native(FILE *stream, const char *format, va_list args) {
    static int (*fn)(FILE *, const char *, va_list) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "vfprintf");
    }
    return fn(stream, format, args);
}

int feof_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "feof");
    }
    return fn(stream);
}

int ferror_native(FILE *stream) {
    static int (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "ferror");
    }
    return fn(stream);
}

void clearerr_native(FILE *stream) {
    static void (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "clearerr");
    }
    fn(stream);
}

int fseek_native(FILE *stream, long offset, int whence) {
    static int (*fn)(FILE *, long, int) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fseek");
    }
    return fn(stream, offset, whence);
}

long ftell_native(FILE *stream) {
    static long (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "ftell");
    }
    return fn(stream);
}

void rewind_native(FILE *stream) {
    static void (*fn)(FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "rewind");
    }
    fn(stream);
}

void setbuf_native(FILE *stream, char *buf) {
    static void (*fn)(FILE *, char *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "setbuf");
    }
    fn(stream, buf);
}

int setvbuf_native(FILE *stream, char *buf, int mode, size_t size) {
    static int (*fn)(FILE *, char *, int, size_t) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "setvbuf");
    }
    return fn(stream, buf, mode, size);
}

int fputs_native(const char *s, FILE *stream) {
    static int (*fn)(const char *, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fputs");
    }
    return fn(s, stream);
}

int fputc_native(int c, FILE *stream) {
    static int (*fn)(int, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "fputc");
    }
    return fn(c, stream);
}

int ungetc_native(int c, FILE *stream) {
    static int (*fn)(int, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "ungetc");
    }
    return fn(c, stream);
}

ssize_t getdelim_native(char **lineptr, size_t *n, int delim, FILE *stream) {
    static ssize_t (*fn)(char **, size_t *, int, FILE *) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "getdelim");
    }
    return fn(lineptr, n, delim, stream);
}

int vfscanf_native(FILE *stream, const char *format, va_list ap) {
    static int (*fn)(FILE *, const char *, va_list) = NULL;
    if (!fn) {
        fn = dlsym(RTLD_NEXT, "vfscanf");
    }
    return fn(stream, format, ap);
}
