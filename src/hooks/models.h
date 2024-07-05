#ifndef NETFUZZLIB_MODELS_H
#define NETFUZZLIB_MODELS_H

#include <stdio.h>
#include <ifaddrs.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/select.h>
#include "sockets/network_types.h"

int socket_nfl(int domain, int type, int protocol);
int bind_nfl(nfl_sock_t *sock, const nfl_addr_t *addr, socklen_t len);
int connect_nfl(nfl_sock_t *sock, const nfl_addr_t *addr, socklen_t addrlen);
int accept_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *len);
int accept4_nfl(nfl_sock_t *sock, nfl_addr_t *addr, socklen_t *len, int flags);
int getpeername_nfl(nfl_sock_t *sock, nfl_addr_t *address, socklen_t *addrlen);
int getsockname_nfl(nfl_sock_t *sock, nfl_addr_t *address, socklen_t *addrlen);
int getsockopt_nfl(nfl_sock_t *sock, int level, int option_name, void *option_value, socklen_t *option_len);
int setsockopt_nfl(nfl_sock_t *sock, int level, int option_name, const void *option_value, socklen_t option_len);
int listen_nfl(nfl_sock_t *sock, int backlog);

int close_nfl_fd(int fd);
int close_nfl_sock(nfl_sock_t *sock);

int shutdown_nfl(nfl_sock_t *sock, int how);
int select_nfl(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds);
int poll_nfl(struct pollfd *fds, nfds_t nfds, int timeout);

int ioctl_nfl(nfl_sock_t *sock, unsigned long request, void *argp);
int vioctl_nfl(nfl_sock_t *sock, unsigned long request, va_list argp);
int pipe_nfl(int filedes[2]);
ssize_t read_nfl(nfl_sock_t *sock, void *buf, size_t count);
ssize_t recvfrom_nfl(nfl_sock_t *sock, void *buf, size_t len, int flags, nfl_addr_t *remote_addr, socklen_t *addrlen);
ssize_t recvmsg_nfl(nfl_sock_t *sock, struct msghdr *msg, int flags);
int recvmmsg_nfl(nfl_sock_t *sock, void *msgvec, unsigned int vlen, int flags, struct timespec *timeout);
ssize_t write_nfl(nfl_sock_t *sock, void const *buf, size_t len);
ssize_t sendto_nfl(nfl_sock_t *sock, const void *buf, size_t len, int flags, const nfl_addr_t *remote_addr, socklen_t addrlen);
ssize_t sendmsg_nfl(nfl_sock_t *sock, const struct msghdr *msg, int flags);

int fcntl_nfl(nfl_sock_t *sock, int cmd, ...);
unsigned int if_nametoindex_nfl(const char *name);
char *if_indextoname_nfl(unsigned int index, char *ifname);

int getifaddrs_nfl(struct ifaddrs **ifap);
void freeifaddrs_nfl(struct ifaddrs *ifa);

int dup_nfl_sock(nfl_sock_t *old_sock);
int dup_nfl_fd(int oldfd);
int dup2_nfl(int oldfd, int newfd);
int dup3_nfl(int oldfd, int newfd, int flags);

size_t fread_nfl(void *ptr, size_t size, size_t nmemb, nfl_sock_t *sock);
size_t fwrite_nfl(const void *ptr, size_t size, size_t nmemb, nfl_sock_t *sock);
char *fgets_nfl(char *s, int size, nfl_sock_t *sock);
int fgetc_nfl(nfl_sock_t *sock);

int close_range_nfl(unsigned int low_fd, unsigned int max_fd, int flags);

#endif //NETFUZZLIB_MODELS_H
