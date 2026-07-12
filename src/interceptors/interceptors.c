#include <stdarg.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <ifaddrs.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include "interceptors.h"

#include <stdlib.h>

#include "core/network_types.h"
#include <netdb.h>
#include <netfuzzlib/api.h>
#include <netfuzzlib/types.h>

#include "core/getifaddrs.h"
#include "core/interfaces.h"
#include "core/ioctl.h"
#include "core/resolver.h"
#include "native.h"

bool is_socket_supported(int domain, int type, int protocol) {
    if (domain == AF_INET || domain == AF_INET6) {
        switch (type) {
        case SOCK_STREAM:
            return protocol == 0 || protocol == IPPROTO_TCP;
        case SOCK_DGRAM:
            return protocol == 0 || protocol == IPPROTO_UDP || protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6;
        case SOCK_RAW:
            return protocol == IPPROTO_ICMP || protocol == IPPROTO_ICMPV6;
        default:
            return false;
        }
    }
    if (domain == AF_NETLINK) {
        return protocol == NETLINK_ROUTE && (type == SOCK_DGRAM || type == SOCK_RAW);
    }
    return false;
}

int socket(int domain, int type, int protocol) {
    const int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (is_socket_supported(domain, base_type, protocol)) {
        return socket_nfl(domain, type, protocol);
    }
    const int fd = socket_native(domain, type, protocol);
    if (domain == AF_UNIX) {
        nfl_log("Socket syscall forwarded to OS, domain=AF_UNIX, type=%d, protocol=%d, new fd=%d", type, protocol, fd);
    } else {
        nfl_log("Socket syscall forwarded to OS, domain=%d, type=%d, protocol=%d, new fd=%d", domain, type, protocol, fd);
    }
    return fd;
}

int bind(int fd, const struct sockaddr *addr, socklen_t len) {
    SWITCH_MODEL_NATIVE(fd, bind_nfl, bind_native, addr, len);
}

int connect(int fd, const struct sockaddr *addr, socklen_t len) {
    SWITCH_MODEL_NATIVE(fd, connect_nfl, connect_native, addr, len);
}

int accept(int fd, struct sockaddr *addr, socklen_t *len) {
    SWITCH_MODEL_NATIVE(fd, accept_nfl, accept_native, addr, len);
}

int accept4(int fd, struct sockaddr *addr, socklen_t *len, int flags) {
    SWITCH_MODEL_NATIVE(fd, accept4_nfl, accept4_native, addr, len, flags);
}

int getpeername(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    SWITCH_MODEL_NATIVE(fd, getpeername_nfl, getpeername_native, addr, addrlen);
}

int getsockname(int fd, struct sockaddr *addr, socklen_t *addrlen) {
    SWITCH_MODEL_NATIVE(fd, getsockname_nfl, getsockname_native, addr, addrlen);
}

int getsockopt(int fd, int level, int option_name, void *option_value, socklen_t *option_len) {
    SWITCH_MODEL_NATIVE(fd, getsockopt_nfl, getsockopt_native, level, option_name, option_value, option_len);
}

int setsockopt(int fd, int level, int option_name, const void *option_value, socklen_t option_len) {
    SWITCH_MODEL_NATIVE(fd, setsockopt_nfl, setsockopt_native, level, option_name, option_value, option_len);
}

int listen(int fd, int backlog) {
    SWITCH_MODEL_NATIVE(fd, listen_nfl, listen_native, backlog);
}

int close(int fd) {
    if (fd >= NFL_RESERVED_FD_START && fd <= NFL_RESERVED_FD_MAX) {
        return 0;
    }

    if (is_nfl_sock_fd(fd)) {
        return close_nfl_fd(fd);
    }
    if (nfl_fd_is_closed_placeholder(fd)) {
        /* Closing it natively would release the number back to the kernel. */
        errno = EBADF;
        return -1;
    }
    nfl_log("Forwarding %s() to %s", __func__, native_fd_to_str(fd));
    return close_native(fd);
}

int shutdown(int fd, int how) {
    SWITCH_MODEL_NATIVE(fd, shutdown_nfl, shutdown_native, how);
}

int ioctl(int fd, unsigned long request, ...) {
    va_list ap;
    va_start(ap, request);
    void *argp = va_arg(ap, void *);
    va_end(ap);
    SWITCH_MODEL_NATIVE(fd, ioctl_nfl, ioctl_native, request, argp);
}

ssize_t read(int fd, void *buf, size_t count) {
    SWITCH_MODEL_NATIVE(fd, read_nfl, read_native, buf, count);
}

ssize_t __read_chk(int fd, void *buf, size_t count, size_t buflen) {
    (void)buflen;
    SWITCH_MODEL_NATIVE(fd, read_nfl, read_native, buf, count);
}

ssize_t recv(int fd, void *buf, size_t buflen, int flags) {
    return recvfrom(fd, buf, buflen, flags, NULL, NULL);
}

ssize_t __recv_chk(int fd, void *buf, size_t len, size_t buflen, int flags) {
    (void)buflen;
    return recvfrom(fd, buf, len, flags, NULL, NULL);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *remote_addr, socklen_t *addrlen) {
    SWITCH_MODEL_NATIVE(fd, recvfrom_nfl, recvfrom_native, buf, len, flags, remote_addr, addrlen);
}

ssize_t __recvfrom_chk(int fd, void *buf, size_t len, size_t buflen, int flags,
                       struct sockaddr *remote_addr, socklen_t *addrlen) {
    (void)buflen;
    SWITCH_MODEL_NATIVE(fd, recvfrom_nfl, recvfrom_native, buf, len, flags, remote_addr, addrlen);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    SWITCH_MODEL_NATIVE(fd, recvmsg_nfl, recvmsg_native, msg, flags);
}

int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    SWITCH_MODEL_NATIVE(fd, recvmmsg_nfl, recvmmsg_native, msgvec, vlen, flags, timeout);
}

ssize_t readv(int fd, const struct iovec *iov, int iovcnt) {
    SWITCH_MODEL_NATIVE(fd, readv_nfl, readv_native, iov, iovcnt);
}

ssize_t write(int fd, void const *buf, size_t len) {
    SWITCH_MODEL_NATIVE(fd, write_nfl, write_native, buf, len);
}

ssize_t send(int fd, const void *buf, size_t len, int flags) {
    return sendto(fd, buf, len, flags, NULL, 0);
}

ssize_t sendto(int fd, const void *buf, size_t len, int flags, const struct sockaddr *remote_addr, socklen_t addrlen) {
    SWITCH_MODEL_NATIVE(fd, sendto_nfl, sendto_native, buf, len, flags, remote_addr, addrlen);
}

ssize_t sendmsg(int fd, const struct msghdr *msg, int flags) {
    SWITCH_MODEL_NATIVE(fd, sendmsg_nfl, sendmsg_native, msg, flags);
}

int sendmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags) {
    SWITCH_MODEL_NATIVE(fd, sendmmsg_nfl, sendmmsg_native, msgvec, vlen, flags);
}

ssize_t writev(int fd, const struct iovec *iov, int iovcnt) {
    SWITCH_MODEL_NATIVE(fd, writev_nfl, writev_native, iov, iovcnt);
}

ssize_t sendfile(int out_fd, int in_fd, off_t *offset, size_t count) {
    SWITCH_MODEL_NATIVE(out_fd, sendfile_nfl, sendfile_native, in_fd, offset, count);
}

ssize_t sendfile64(int out_fd, int in_fd, off_t *offset, size_t count) {
    return sendfile(out_fd, in_fd, offset, count);
}

int getifaddrs(struct ifaddrs **ifap) {
    return getifaddrs_nfl(ifap);
}

void freeifaddrs(struct ifaddrs *ifa) {
    return freeifaddrs_nfl(ifa);
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints, struct addrinfo **res) {
    return resolver_getaddrinfo(node, service, hints, res);
}

void freeaddrinfo(struct addrinfo *res) {
    resolver_freeaddrinfo(res);
}

int getnameinfo(const struct sockaddr *sa, socklen_t salen,
                char *host, socklen_t hostlen,
                char *serv, socklen_t servlen, int flags) {
    return resolver_getnameinfo(sa, salen, host, hostlen, serv, servlen, flags);
}

struct hostent *gethostbyname(const char *name) {
    struct hostent *r = resolver_gethostbyname(name);
    h_errno = *resolver_h_errno_ptr();
    return r;
}

struct hostent *gethostbyname2(const char *name, int af) {
    struct hostent *r = resolver_gethostbyname2(name, af);
    h_errno = *resolver_h_errno_ptr();
    return r;
}

int fcntl64(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *argp = va_arg(ap, void *);
    va_end(ap);
    SWITCH_MODEL_NATIVE(fd, fcntl_nfl, fcntl64_native, cmd, argp);
}

int fcntl(int fd, int cmd, ...) {
    va_list ap;
    va_start(ap, cmd);
    void *argp = va_arg(ap, void *);
    va_end(ap);
    SWITCH_MODEL_NATIVE(fd, fcntl_nfl, fcntl_native, cmd, argp);
}

/* Duplicating a placeholder natively would hand the SUT a working /dev/null. */
static bool dup_source_is_closed(int oldfd) {
    if (!nfl_fd_is_closed_placeholder(oldfd)) {
        return false;
    }
    errno = EBADF;
    return true;
}

int dup(int oldfd) {
    errno = 0;
    if (dup_source_is_closed(oldfd)) {
        return -1;
    }
    return is_nfl_sock_fd(oldfd) ? dup_nfl_fd(oldfd) : dup_native(oldfd);
}

int dup2(int oldfd, int newfd) {
    errno = 0;
    if (dup_source_is_closed(oldfd)) {
        return -1;
    }
    return is_nfl_sock_fd(oldfd) ? dup2_nfl(oldfd, newfd) : dup2_native(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags) {
    errno = 0;
    if (dup_source_is_closed(oldfd)) {
        return -1;
    }
    return is_nfl_sock_fd(oldfd) ? dup3_nfl(oldfd, newfd, flags) : dup3_native(oldfd, newfd, flags);
}

unsigned int if_nametoindex(const char *name) {
    return if_nametoindex_nfl(name);
}

struct if_nameindex *if_nameindex(void) {
    return if_nameindex_nfl();
}

void if_freenameindex(struct if_nameindex *ptr) {
    if_freenameindex_nfl(ptr);
}

char *if_indextoname(unsigned int index, char *ifname) {
    return if_indextoname_nfl(index, ifname);
}

static void close_range_native_keep_pool(const unsigned int lo, const unsigned int hi, const int flags) {
    if (lo > hi) {
        return;
    }
    if (lo >= NFL_FD_TABLE_SIZE) {
        close_range_native(lo, hi, flags);
        return;
    }
    const unsigned int scan_hi = hi < NFL_FD_TABLE_SIZE - 1 ? hi : NFL_FD_TABLE_SIZE - 1;
    long run_start = -1;
    for (unsigned int fd = lo; fd <= scan_hi; fd++) {
        if (!nfl_fd_is_pool((int)fd)) {
            if (run_start < 0) {
                run_start = (long)fd;
            }
            continue;
        }
        if (run_start >= 0) {
            close_range_native((unsigned int)run_start, fd - 1, flags);
            run_start = -1;
        }
    }
    if (run_start >= 0) {
        close_range_native((unsigned int)run_start, scan_hi, flags);
    }
    if (hi > scan_hi) {
        close_range_native(scan_hi + 1, hi, flags);
    }
}

void closefrom(int low_fd) {
    errno = 0;
    if (low_fd > NFL_RESERVED_FD_MAX) {
        closefrom_native(low_fd);
        return;
    }
    close_range_native_keep_pool((unsigned int)low_fd, NFL_RESERVED_FD_START - 1, 0);
    closefrom_native(NFL_RESERVED_FD_MAX + 1);
    close_range_nfl(low_fd, NFL_FD_TABLE_SIZE - 1);
}

int close_range(unsigned int low_fd, unsigned int max_fd, int flags) {
    errno = 0;
    if (low_fd > NFL_RESERVED_FD_MAX) {
        close_range_native(low_fd, max_fd, flags);
    } else if (max_fd < NFL_RESERVED_FD_START) {
        close_range_native_keep_pool(low_fd, max_fd, flags);
    } else {
        close_range_native_keep_pool(low_fd, NFL_RESERVED_FD_START - 1, flags);
        if (max_fd > NFL_RESERVED_FD_MAX) {
            close_range_native(NFL_RESERVED_FD_MAX + 1, max_fd, flags);
        }
    }
    if (flags & CLOSE_RANGE_CLOEXEC) {
        return 0;
    }
    return close_range_nfl(low_fd, max_fd);
}

char *native_fd_to_str(int fd) {
    if (fd < 0 || fd >= NFL_FD_TABLE_SIZE) {
        return "fd out of range";
    }
    static char *native_fds_description_cache[NFL_FD_TABLE_SIZE] = { NULL };

    if (native_fds_description_cache[fd]) {
        free(native_fds_description_cache[fd]);
        native_fds_description_cache[fd] = NULL;
    }
    char path[50];
    struct stat my_stat;

    snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);
    if (lstat(path, &my_stat) < 0) {
        nfl_log("Could not read %s", path);
        native_fds_description_cache[fd] = calloc(1, 1);
        if (!native_fds_description_cache[fd]) {
            nfl_die(1, "Out of memory in native_fd_to_str()");
        }
        return native_fds_description_cache[fd];
    }
    size_t len = sizeof("native fd: 922337203685477580700 | ") + my_stat.st_size;
    char *description = calloc(1, len);
    if (!description) {
        nfl_die(1, "Out of memory in native_fd_to_str()");
    }
    int offset = snprintf(description, len, "native fd: %d | ", fd);
    ssize_t link_len = readlink(path, description + offset, len - offset - 1);
    // Bound-check satisfies analyzer: readlink wrote at most len-offset-1 bytes, so offset+link_len <= len-1
    if (link_len > 0 && (size_t)offset + (size_t)link_len < len) {
        description[offset + link_len] = '\0'; // NOLINT(clang-analyzer-security.ArrayBound)
    } else {
        description[offset] = '\0';
    }
    native_fds_description_cache[fd] = description;
    return description;
}
