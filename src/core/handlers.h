#ifndef NETFUZZLIB_HANDLERS_H
#define NETFUZZLIB_HANDLERS_H

#include <stdio.h>
#include <sys/poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include "network_types.h"

int socket_nfl(int domain, int type, int protocol);
int bind_nfl(nfl_sock_full_t *sock, const nfl_addr_t *addr, socklen_t len);
int connect_nfl(nfl_sock_full_t *sock, const nfl_addr_t *addr, socklen_t addrlen);
int accept_nfl(nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *len);
int accept4_nfl(nfl_sock_full_t *sock, nfl_addr_t *addr, socklen_t *len, int flags);
int getpeername_nfl(const nfl_sock_full_t *sock, nfl_addr_t *address, socklen_t *addrlen);
int getsockname_nfl(const nfl_sock_full_t *sock, nfl_addr_t *address, socklen_t *addrlen);
int getsockopt_nfl(const nfl_sock_full_t *sock, int level, int option_name, void *option_value, socklen_t *option_len);
int setsockopt_nfl(nfl_sock_full_t *sock, int level, int option_name, const void *option_value, socklen_t option_len);
int listen_nfl(nfl_sock_full_t *sock, int backlog);
int shutdown_nfl(nfl_sock_full_t *sock, int how);

int select_nfl(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, bool blocking);
int poll_nfl(struct pollfd *fds, nfds_t nfds, int timeout);

uint32_t nfl_sock_poll(nfl_sock_full_t *sock, uint32_t interest);
uint32_t sock_poll_with_gap(nfl_sock_full_t *sock, uint32_t interest, bool blocking);
void sock_idle_tick(nfl_sock_full_t *sock);
void sock_idle_clear(nfl_sock_full_t *sock);

ssize_t read_nfl(nfl_sock_full_t *sock, void *buf, size_t count);
ssize_t readv_nfl(nfl_sock_full_t *sock, const struct iovec *iov, int iovcnt);
ssize_t recvfrom_nfl(nfl_sock_full_t *sock, void *buf, size_t len, int flags, nfl_addr_t *remote_addr, socklen_t *addrlen);
ssize_t recvmsg_nfl(nfl_sock_full_t *sock, struct msghdr *msg, int flags);
int recvmmsg_nfl(nfl_sock_full_t *sock, struct mmsghdr *msgvec, unsigned int vlen, int flags, const struct timespec *timeout);

ssize_t write_nfl(nfl_sock_full_t *sock, void const *buf, size_t len);
ssize_t writev_nfl(nfl_sock_full_t *sock, const struct iovec *iov, int iovcnt);
ssize_t sendto_nfl(nfl_sock_full_t *sock, const void *buf, size_t len, int flags, const nfl_addr_t *remote_addr, socklen_t addrlen);
ssize_t sendmsg_nfl(nfl_sock_full_t *sock, const struct msghdr *msg, int flags);
int sendmmsg_nfl(nfl_sock_full_t *sock, struct mmsghdr *msgvec, unsigned int vlen, int flags);
ssize_t sendfile_nfl(nfl_sock_full_t *sock, int in_fd, off_t *offset, size_t count);

int fcntl_nfl(nfl_sock_full_t *sock, int cmd, void *argp);

int dup_nfl_sock(nfl_sock_full_t *old_sock);
int dup_nfl_fd(int oldfd);
int dup2_nfl(int oldfd, int newfd);
int dup3_nfl(int oldfd, int newfd, int flags);

size_t fread_nfl(void *ptr, size_t size, size_t nmemb, nfl_sock_full_t *sock);
size_t fwrite_nfl(const void *ptr, size_t size, size_t nmemb, nfl_sock_full_t *sock);
char *fgets_nfl(char *s, int size, nfl_sock_full_t *sock);
int fgetc_nfl(nfl_sock_full_t *sock);
int ungetc_nfl(int c, nfl_sock_full_t *sock);
int fputs_nfl(const char *s, nfl_sock_full_t *sock);
int fputc_nfl(int c, nfl_sock_full_t *sock);
ssize_t getdelim_nfl(char **lineptr, size_t *n, int delim, nfl_sock_full_t *sock);

#endif // NETFUZZLIB_HANDLERS_H
