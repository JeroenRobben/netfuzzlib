#include <dlfcn.h>
#include <unistd.h>
#include "native.h"
#include <netfuzzlib/api.h>

int socket_native(int domain, int type, int protocol) {
    static int (*socket_libc)(int, int, int) = NULL;
    if (!socket_libc)
        socket_libc = dlsym(RTLD_NEXT, "socket");
    socket_libc = dlsym(RTLD_NEXT, "socket");
    return (*socket_libc)(domain, type, protocol);
}

int bind_native(int fd, const struct sockaddr *addr, socklen_t len) {
    static int (*bind_libc)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!bind_libc)
        bind_libc = dlsym(RTLD_NEXT, "bind");
    return (*bind_libc)(fd, addr, len);
}

int connect_native(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    static int (*connect_libc)(int, const struct sockaddr *, socklen_t) = NULL;
    if (!connect_libc)
        connect_libc = dlsym(RTLD_NEXT, "connect");
    return (*connect_libc)(fd, addr, addrlen);
}

int accept_native(int fd, struct sockaddr *addr, socklen_t *len) {
    static int (*accept_libc)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!accept_libc)
        accept_libc = dlsym(RTLD_NEXT, "accept");
    return (*accept_libc)(fd, addr, len);
}

int accept4_native(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    static int (*accept4_libc)(int, struct sockaddr *, socklen_t *, int) = NULL;
    if (!accept4_libc)
        accept4_libc = dlsym(RTLD_NEXT, "accept4");
    return (*accept4_libc)(fd, addr, len, flags);
}

int getpeername_native(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*getpeername_libc)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!getpeername_libc)
        getpeername_libc = dlsym(RTLD_NEXT, "getpeername");
    return (*getpeername_libc)(fd, addr, addrlen);
}

int getsockname_native(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    static int (*getsockname_libc)(int, struct sockaddr *, socklen_t *) = NULL;
    if (!getsockname_libc)
        getsockname_libc = dlsym(RTLD_NEXT, "getsockname");
    return (*getsockname_libc)(fd, addr, addrlen);
}

int getsockopt_native(int fd, int level, int option_name, void *option_value, socklen_t *option_len) {
    static int (*getsockopt_libc)(int, int, int, void *, socklen_t *) = NULL;
    if (!getsockopt_libc)
        getsockopt_libc = dlsym(RTLD_NEXT, "getsockopt");
    return (*getsockopt_libc)(fd, level, option_name, option_value, option_len);
}

int setsockopt_native(int fd, int level, int option_name, const void *option_value, socklen_t option_len) {
    static int (*setsockopt_libc)(int, int, int, const void *, socklen_t) = NULL;
    if (!setsockopt_libc)
        setsockopt_libc = dlsym(RTLD_NEXT, "setsockopt");
    return (*setsockopt_libc)(fd, level, option_name, option_value, option_len);
}

int listen_native(int fd, int backlog) {
    static int (*listen_libc)(int, int) = NULL;
    if (!listen_libc)
        listen_libc = dlsym(RTLD_NEXT, "listen");
    return (*listen_libc)(fd, backlog);
}

int close_native(int fd) {
    static int (*close_libc)(int) = NULL;
    if (!close_libc)
        close_libc = dlsym(RTLD_NEXT, "close");
    return (*close_libc)(fd);
}

int shutdown_native(int fd, int how) {
    static int (*shutdown_libc)(int, int) = NULL;
    if (!shutdown_libc)
        shutdown_libc = dlsym(RTLD_NEXT, "shutdown");
    return (*shutdown_libc)(fd, how);
}

int select_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    static int (*select_libc)(int, fd_set *, fd_set *, fd_set *, struct timeval *) = NULL;
    if (!select_libc)
        select_libc = dlsym(RTLD_NEXT, "select");
    return (*select_libc)(nfds, readfds, writefds, exceptfds, timeout);
}

int pselect_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    static int (*pselect_libc)(int, fd_set *, fd_set *, fd_set *, const struct timespec *, const sigset_t *) = NULL;
    if (!pselect_libc)
        pselect_libc = dlsym(RTLD_NEXT, "pselect");
    return (*pselect_libc)(nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int poll_native(struct pollfd *fds, nfds_t nfds, int timeout) {
    static int (*poll_libc)(struct pollfd *, nfds_t, int) = NULL;
    if (!poll_libc)
        poll_libc = dlsym(RTLD_NEXT, "poll");
    return (*poll_libc)(fds, nfds, timeout);
}

int ppoll_native(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    static int (*ppoll_libc)(struct pollfd *, nfds_t, const struct timespec *, const sigset_t *) = NULL;
    if (!ppoll_libc)
        ppoll_libc = dlsym(RTLD_NEXT, "ppoll");
    return (*ppoll_libc)(fds, nfds, timeout_ts, sigmask);
}

int ioctl_native(int fd, unsigned long request, void *argp) {
    static int (*ioctl_libc)(int, unsigned long, void *) = NULL;
    if (!ioctl_libc)
        ioctl_libc = dlsym(RTLD_NEXT, "ioctl");
    return (*ioctl_libc)(fd, request, argp);
}

int pipe_native(int filedes[2]) {
    static int (*pipe_libc)(int[2]) = NULL;
    if (!pipe_libc)
        pipe_libc = dlsym(RTLD_NEXT, "pipe");
    return (*pipe_libc)(filedes);
}

ssize_t read_native(int fd, void *buf, size_t count) {
    static int (*read_libc)(int, void *, size_t) = NULL;
    if (!read_libc)
        read_libc = dlsym(RTLD_NEXT, "read");
    return (*read_libc)(fd, buf, count);
}

ssize_t recvfrom_native(int fd, void *buf, size_t len, int flags, struct sockaddr *remote_addr, socklen_t *addrlen) {
    static int (*recvfrom_libc)(int, void *, size_t, int, struct sockaddr *, socklen_t *) = NULL;
    if (!recvfrom_libc)
        recvfrom_libc = dlsym(RTLD_NEXT, "recvfrom");
    return (*recvfrom_libc)(fd, buf, len, flags, remote_addr, addrlen);
}

ssize_t recvmsg_native(int fd, struct msghdr *msg, int flags) {
    static int (*recvmsg_libc)(int, struct msghdr *, int) = NULL;
    if (!recvmsg_libc)
        recvmsg_libc = dlsym(RTLD_NEXT, "recvmsg");
    return (*recvmsg_libc)(fd, msg, flags);
}

int recvmmsg_native(int fd, void *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    static int (*recvmmsg_libc)(int, void *, unsigned int, int, struct timespec *) = NULL;
    if (!recvmmsg_libc)
        recvmmsg_libc = dlsym(RTLD_NEXT, "recvmmsg");
    return (*recvmmsg_libc)(fd, msgvec, vlen, flags, timeout);
}

ssize_t write_native(int fd, void const *buf, size_t len) {
    static int (*write_libc)(int, void const *, size_t) = NULL;
    if (!write_libc)
        write_libc = dlsym(RTLD_NEXT, "write");
    return (*write_libc)(fd, buf, len);
}

ssize_t sendto_native(int fd, const void *buf, size_t len, int flags, const struct sockaddr *remote_addr, socklen_t addrlen) {
    static int (*sendto_libc)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = NULL;
    if (!sendto_libc)
        sendto_libc = dlsym(RTLD_NEXT, "sendto");
    return (*sendto_libc)(fd, buf, len, flags, remote_addr, addrlen);
}

ssize_t sendmsg_native(int fd, const struct msghdr *msg, int flags) {
    static int (*sendmsg_libc)(int, const struct msghdr *, int) = NULL;
    if (!sendmsg_libc)
        sendmsg_libc = dlsym(RTLD_NEXT, "sendmsg");
    return (*sendmsg_libc)(fd, msg, flags);
}

int fcntl_native(int fd, int cmd, ...) {
    static int (*fnctl_libc)(int, int, ...) = NULL;
    if (!fnctl_libc)
        fnctl_libc = dlsym(RTLD_NEXT, "fcntl");
    va_list ap;
    long arg;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
    return (*fnctl_libc)(fd, cmd, arg);
}

int fcntl64_native(int fd, int cmd, ...) {
    static int (*fnctl64_libc)(int, int, ...) = NULL;
    if (!fnctl64_libc)
        fnctl64_libc = dlsym(RTLD_NEXT, "fcntl64");
    va_list ap;
    long arg;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
    return (*fnctl64_libc)(fd, cmd, arg);
}

int dup_native(int oldfd) {
    static int (*dup_libc)(int) = NULL;
    if (!dup_libc)
        dup_libc = dlsym(RTLD_NEXT, "dup");
    return (*dup_libc)(oldfd);
}

int dup2_native(int oldfd, int newfd) {
    static int (*dup2_libc)(int, int) = NULL;
    if (!dup2_libc)
        dup2_libc = dlsym(RTLD_NEXT, "dup2");
    return (*dup2_libc)(oldfd, newfd);
}

int dup3_native(int oldfd, int newfd, int flags) {
    static int (*dup3_libc)(int, int, int) = NULL;
    if (!dup3_libc)
        dup3_libc = dlsym(RTLD_NEXT, "dup3");
    return (*dup3_libc)(oldfd, newfd, flags);
}

int fileno_native(FILE *stream) {
    static int (*fileno_libc)(FILE *) = NULL;
    if (!fileno_libc)
        fileno_libc = dlsym(RTLD_NEXT, "fileno");
    return (*fileno_libc)(stream);
}

FILE *fdopen_native(int fd, const char *mode) {
    static FILE *(*fdopen_libc)(int, const char *) = NULL;
    if (!fdopen_libc)
        fdopen_libc = dlsym(RTLD_NEXT, "fdopen");
    return (*fdopen_libc)(fd, mode);
}

char *fgets_native(char *s, int size, FILE *stream) {
    static char *(*fgets_libc)(char *, int, FILE *) = NULL;
    if (!fgets_libc)
        fgets_libc = dlsym(RTLD_NEXT, "fgets");
    return (*fgets_libc)(s, size, stream);
}

int fgetc_native(FILE *stream) {
    static int (*fgetc_libc)(FILE *) = NULL;
    if (!fgetc_libc)
        fgetc_libc = dlsym(RTLD_NEXT, "fgetc");
    return (*fgetc_libc)(stream);
}

size_t fread_native(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*fread_libc)(void *, size_t, size_t, FILE *) = NULL;
    if (!fread_libc)
        fread_libc = dlsym(RTLD_NEXT, "fread");
    return (*fread_libc)(ptr, size, nmemb, stream);
}

size_t fwrite_native(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    static size_t (*fwrite_libc)(const void *, size_t, size_t, FILE *) = NULL;
    if (!fwrite_libc)
        fwrite_libc = dlsym(RTLD_NEXT, "fwrite");
    return (*fwrite_libc)(ptr, size, nmemb, stream);
}

int fclose_native(FILE *stream) {
    static int (*fclose_libc)(FILE *) = NULL;
    if (!fclose_libc)
        fclose_libc = dlsym(RTLD_NEXT, "fclose");
    return (*fclose_libc)(stream);
}

int fflush_native(FILE *stream) {
    static int (*fflush_libc)(FILE *) = NULL;
    if (!fflush_libc)
        fflush_libc = dlsym(RTLD_NEXT, "fflush");
    return (*fflush_libc)(stream);
}

int vfprintf_native(FILE *stream, const char *format, va_list args) {
    static int (*vfprintf_libc)(FILE *, const char *, va_list) = NULL;
    if (!vfprintf_libc)
        vfprintf_libc = dlsym(RTLD_NEXT, "vfprintf");
    return (*vfprintf_libc)(stream, format, args);
}

void closefrom_native(int low_fd) {
    static void (*closefrom_libc)(int) = NULL;
    if (!closefrom_libc)
        closefrom_libc = dlsym(RTLD_NEXT, "closefrom");
    (*closefrom_libc)(low_fd);
}

int close_range_native(unsigned int low_fd, unsigned int max_fd, unsigned int flags) {
    static int (*close_range_libc)(unsigned int, unsigned int, unsigned int) = NULL;
    if (!close_range_libc)
        close_range_libc = dlsym(RTLD_NEXT, "close_range");
    return (*close_range_libc)(low_fd, max_fd, flags);
}