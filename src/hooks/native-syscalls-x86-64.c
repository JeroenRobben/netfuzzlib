#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "native.h"
#include "log.h"

int socket_native(int domain, int type, int protocol) {
    return syscall(__NR_socket, domain, type, protocol);
}

int bind_native(int fd, const struct sockaddr *addr, socklen_t len) {
    return (int)syscall(__NR_bind, fd, addr, len);
}

int connect_native(int fd, const struct sockaddr *addr, socklen_t addrlen) {
    return (int)syscall(__NR_connect, fd, addr, addrlen);
}

int accept_native(int fd, struct sockaddr *addr, socklen_t *len) {
#ifdef __NR_accept
    return (int)syscall(__NR_accept, fd, addr, len);
#else
    return (int)syscall(43, fd, addr, len);
#endif
}

int accept4_native(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    return (int)syscall(__NR_accept4, fd, addr, len, flags);
}

int getpeername_native(int fd, struct sockaddr *address, socklen_t *addrlen) {
    return (int)syscall(__NR_getpeername, fd, address, addrlen);
}
int getsockname_native(int fd, struct sockaddr *address, socklen_t *addrlen) {
    return (int)syscall(__NR_getsockname, fd, address, addrlen);
}
int getsockopt_native(int fd, int level, int option_name, void *option_value, socklen_t *option_len) {
    return (int)syscall(__NR_getsockopt, fd, level, option_name, option_value, option_len);
}
int setsockopt_native(int fd, int level, int option_name, const void *option_value, socklen_t option_len) {
    return (int)syscall(__NR_setsockopt, fd, level, option_name, option_value, option_len);
}
int listen_native(int fd, int backlog) {
    return (int)syscall(__NR_listen, fd, backlog);
}

int close_native(int fd) {
    return (int)syscall(__NR_close, fd);
}

int shutdown_native(int fd, int how) {
    return (int)syscall(__NR_shutdown, fd, how);
}

ssize_t read_native(int fd, void *buf, size_t count) {
    return syscall(__NR_read, fd, buf, count);
}

ssize_t recvfrom_native(int fd, void *buf, size_t len, int flags, struct sockaddr *remote_addr, socklen_t *addrlen) {
    return syscall(__NR_recvfrom, fd, buf, len, flags, remote_addr, addrlen);
}
ssize_t recvmsg_native(int fd, struct msghdr *msg, int flags) {
    return syscall(__NR_recvmsg, fd, msg, flags);
}

int recvmmsg_native(int fd, void *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    return (int)syscall(__NR_recvmmsg, fd, msgvec, vlen, flags, timeout);
}

ssize_t write_native(int fd, const void *buf, size_t len) {
    return syscall(__NR_write, fd, buf, len);
}

ssize_t sendto_native(int fd, const void *buf, size_t len, int flags, const struct sockaddr *remote_addr, socklen_t addrlen) {
    return syscall(__NR_sendto, fd, buf, len, flags, remote_addr, addrlen);
}
ssize_t sendmsg_native(int fd, const struct msghdr *msg, int flags) {
    return syscall(__NR_sendmsg, fd, msg, flags);
}

int ioctl_native(int fd, unsigned long request, void *argp) {
    return (int)syscall(__NR_ioctl, fd, request, argp);
}

int poll_native(struct pollfd *fds, nfds_t nfds, int timeout) {
    return (int)syscall(__NR_poll, fds, nfds, timeout);
}

int ppoll_native(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask) {
    return (int)syscall(__NR_ppoll, fds, nfds, timeout_ts, sigmask);
}

int select_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout) {
    return (int)syscall(__NR_select, nfds, readfds, writefds, exceptfds, timeout);
}

int pselect_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask) {
    return (int)syscall(__NR_pselect6, nfds, readfds, writefds, exceptfds, timeout, sigmask);
}

int pipe_native(int filedes[2]) {
    return (int)syscall(__NR_pipe, filedes);
}

int fcntl_native(int fd, int cmd, ...) {
    va_list ap;
    long arg;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
    return (int)syscall(__NR_fcntl, fd, cmd, arg);
}

int fcntl64_native(int fd, int cmd, ...) {
    va_list ap;
    long arg;
    va_start(ap, cmd);
    arg = va_arg(ap, long);
    va_end(ap);
#ifdef __NR_fcntl64
    return (int)syscall(__NR_fcntl64, fd, cmd, arg);
#else
    return (int)syscall(221, fd, cmd, arg);
}
#endif
}