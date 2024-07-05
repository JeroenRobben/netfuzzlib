#include <stdbool.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <ifaddrs.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include "hooks.h"
#include "sockets/network_types.h"
#include <netfuzzlib/api.h>

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
    } else if (domain == AF_NETLINK) {
        return protocol == NETLINK_ROUTE && (type == SOCK_DGRAM || type == SOCK_RAW);
    }
    return false;
}

int socket(int domain, int type, int protocol) {
    int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (is_socket_supported(domain, base_type, protocol)) {
        return socket_nfl(domain, type, protocol);
    } else {
        int fd = socket_native(domain, type, protocol);
        if (domain == AF_UNIX) {
            nfl_log_info("Socket syscall forwarded to OS, domain=AF_UNIX, type=%d, protocol=%d, new fd=%d", type, protocol, fd);
        } else {
            nfl_log_info("Socket syscall forwarded to OS, domain=%d, type=%d, protocol=%d, new fd=%d", domain, type, protocol, fd);
        }
        return fd;
    }
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

    if (is_nfl_sock_fd((fd))) {
        nfl_sock_t *sock = get_nfl_sock(fd);
        if (!sock) {
            errno = ENOTSOCK;
            return -1;
        }
        return close_nfl_fd(fd);
    } else {
        nfl_log_debug("Forwarding %s() to %s", __func__, native_fd_to_str(fd));
        return close_native(fd);
    }
}

int shutdown(int fd, int how) {
    SWITCH_MODEL_NATIVE(fd, shutdown_nfl, shutdown_native, how);
}

int ioctl(int fd, unsigned long request, void *argp) {
    SWITCH_MODEL_NATIVE(fd, ioctl_nfl, ioctl_native, request, argp);
}

ssize_t read(int fd, void *buf, size_t count) {
    SWITCH_MODEL_NATIVE(fd, read_nfl, read_native, buf, count);
}

ssize_t recv(int fd, void *buf, size_t buflen, int flags) {
    return recvfrom(fd, buf, buflen, flags, NULL, 0);
}

ssize_t recvfrom(int fd, void *buf, size_t len, int flags, struct sockaddr *remote_addr, socklen_t *addrlen) {
    SWITCH_MODEL_NATIVE(fd, recvfrom_nfl, recvfrom_native, buf, len, flags, remote_addr, addrlen);
}

ssize_t recvmsg(int fd, struct msghdr *msg, int flags) {
    SWITCH_MODEL_NATIVE(fd, recvmsg_nfl, recvmsg_native, msg, flags);
}

int recvmmsg(int fd, struct mmsghdr *msgvec, unsigned int vlen, int flags, struct timespec *timeout) {
    SWITCH_MODEL_NATIVE(fd, recvmmsg_nfl, recvmmsg_native, msgvec, vlen, flags, timeout);
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

int getifaddrs(struct ifaddrs **ifap) {
    return getifaddrs_nfl(ifap);
}

void freeifaddrs(struct ifaddrs *ifa) {
    return freeifaddrs_nfl(ifa);
}

int fcntl64(int fd, int cmd, char *argp) {
    SWITCH_MODEL_NATIVE(fd, fcntl_nfl, fcntl64_native, cmd, argp);
}

int fcntl(int fd, int cmd, char *argp) {
    SWITCH_MODEL_NATIVE(fd, fcntl_nfl, fcntl_native, cmd, argp);
}

int dup(int oldfd) {
    errno = 0;
    return is_nfl_sock_fd(oldfd) ? dup_nfl_fd(oldfd) : dup_native(oldfd);
}

int dup2(int oldfd, int newfd) {
    errno = 0;
    return is_nfl_sock_fd(oldfd) ? dup2_nfl(oldfd, newfd) : dup2_native(oldfd, newfd);
}

int dup3(int oldfd, int newfd, int flags) {
    errno = 0;
    return is_nfl_sock_fd(oldfd) ? dup3_nfl(oldfd, newfd, flags) : dup3_native(oldfd, newfd, flags);
}

unsigned int if_nametoindex(const char *name) {
    return if_nametoindex_nfl(name);
}

char *if_indextoname(unsigned int index, char *ifname) {
    return if_indextoname_nfl(index, ifname);
}

//int pipe(int filedes[2]) {
//    int ret = pipe_native(filedes);
//    nfl_log_info("Pipe native called, ret: %d, fds: %d, %d", ret, filedes[0], filedes[1]);
//    return ret;
//}

void closefrom(int low_fd) {
    errno = 0;
    if (low_fd > NFL_RESERVED_FD_MAX) {
        closefrom_native(low_fd);
        return;
    }
    close_range_native(low_fd, NFL_RESERVED_FD_START - 1, 0);
    closefrom_native(NFL_RESERVED_FD_MAX + 1);
    close_range_nfl(low_fd, SOCKET_FD_MAX, 0);
}

int close_range(unsigned int low_fd, unsigned int max_fd, int flags) {
    errno = 0;
    if (max_fd < NFL_RESERVED_FD_START || low_fd > NFL_RESERVED_FD_MAX) {
        close_range_native(low_fd, max_fd, flags);
    } else {
        close_range_native(low_fd, NFL_RESERVED_FD_START - 1, flags);
        close_range_native(NFL_RESERVED_FD_MAX + 1, max_fd, flags);
    }
    if (IS_FLAG_SET(flags, CLOSE_RANGE_CLOEXEC)) {
        return 0;
    }
    return close_range_nfl(low_fd, max_fd, flags);
}

char *native_fd_to_str(int fd) {
    return "native_fd_to_str not enabled";
    if (fd >= SOCKET_FD_MAX) {
        return "fd out of range";
    }
    static char *native_fds_description_cache[SOCKET_FD_MAX] = { 0 };

    if (native_fds_description_cache[fd]) {
        free(native_fds_description_cache[fd]);
        native_fds_description_cache[fd] = NULL;
    }
    char path[50];
    struct stat my_stat;

    snprintf(path, sizeof(path), "/proc/%d/fd/%d", getpid(), fd);
    if (lstat(path, &my_stat) < 0) {
        nfl_log_error("Could not read %s", path);
        native_fds_description_cache[fd] = calloc(1, 1);
        if (!native_fds_description_cache[fd]) {
            nfl_exit_log(1, "Out of memory in native_fd_to_str()");
        }
        return native_fds_description_cache[fd];
    }
    size_t len = sizeof("native fd: 922337203685477580700 | ") + my_stat.st_size;
    char *description = calloc(1, len);
    if (!description) {
        nfl_exit_log(1, "Out of memory in native_fd_to_str()");
    }
    int offset = snprintf(description, len, "native fd: %d | ", fd);
    readlink(path, description + offset, len - offset);
    description[len - 1] = '\0';
    native_fds_description_cache[fd] = description;
    return description;
}