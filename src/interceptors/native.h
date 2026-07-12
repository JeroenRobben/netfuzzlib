#ifndef NETFUZZLIB_NATIVE_H
#define NETFUZZLIB_NATIVE_H

#include <sys/select.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <stdio.h>

int socket_native(int domain, int type, int protocol);
int bind_native(int fd, const struct sockaddr *addr, socklen_t len);
int connect_native(int fd, const struct sockaddr *addr, socklen_t addrlen);
int accept_native(int fd, struct sockaddr *addr, socklen_t *len);
int accept4_native(int fd, struct sockaddr *addr, socklen_t *len, int flags);
int getpeername_native(int fd, struct sockaddr *address, socklen_t *addrlen);
int getsockname_native(int fd, struct sockaddr *address, socklen_t *addrlen);
int getsockopt_native(int fd, int level, int option_name, void *option_value, socklen_t *option_len);
int setsockopt_native(int fd, int level, int option_name, const void *option_value, socklen_t option_len);
int listen_native(int fd, int backlog);
int close_native(int fd);
int shutdown_native(int fd, int how);
int fcntl_native(int fd, int cmd, ...);
int fcntl64_native(int fd, int cmd, ...);

int select_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout);
int pselect_native(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask);

int poll_native(struct pollfd *fds, nfds_t nfds, int timeout);
int ppoll_native(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask);

int epoll_create_native(int size);
int epoll_create1_native(int flags);
int epoll_ctl_native(int epfd, int op, int fd, void *event);
int epoll_wait_native(int epfd, void *events, int maxevents, int timeout);
int epoll_pwait_native(int epfd, void *events, int maxevents, int timeout, const sigset_t *sigmask);
int epoll_pwait2_native(int epfd, void *events, int maxevents, const struct timespec *timeout, const sigset_t *sigmask);

int ioctl_native(int fd, unsigned long request, void *argp);

int pipe_native(int filedes[2]);

ssize_t read_native(int fd, void *buf, size_t count);
ssize_t readv_native(int fd, const struct iovec *iov, int iovcnt);
ssize_t pread_native(int fd, void *buf, size_t count, off_t offset);
ssize_t recvfrom_native(int fd, void *buf, size_t len, int flags, struct sockaddr *remote_addr, socklen_t *addrlen);
ssize_t recvmsg_native(int fd, struct msghdr *msg, int flags);
int recvmmsg_native(int fd, void *msgvec, unsigned int vlen, int flags, struct timespec *timeout);

ssize_t write_native(int fd, void const *buf, size_t len);
ssize_t writev_native(int fd, const struct iovec *iov, int iovcnt);
ssize_t sendto_native(int fd, const void *buf, size_t len, int flags, const struct sockaddr *remote_addr, socklen_t addrlen);
ssize_t sendmsg_native(int fd, const struct msghdr *msg, int flags);
int sendmmsg_native(int fd, void *msgvec, unsigned int vlen, int flags);
ssize_t sendfile_native(int out_fd, int in_fd, off_t *offset, size_t count);

int dup_native(int oldfd);
int dup2_native(int oldfd, int newfd);
int dup3_native(int oldfd, int newfd, int flags);

int fileno_native(FILE *stream);
FILE *fdopen_native(int fd, const char *mode);
char *fgets_native(char *s, int size, FILE *stream);
int fgetc_native(FILE *stream);
size_t fread_native(void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t fwrite_native(const void *ptr, size_t size, size_t nmemb, FILE *stream);
int fclose_native(FILE *stream);
int fflush_native(FILE *stream);
int vfprintf_native(FILE *stream, const char *format, va_list args);
int feof_native(FILE *stream);
int ferror_native(FILE *stream);
void clearerr_native(FILE *stream);
int fseek_native(FILE *stream, long offset, int whence);
long ftell_native(FILE *stream);
void rewind_native(FILE *stream);
void setbuf_native(FILE *stream, char *buf);
int setvbuf_native(FILE *stream, char *buf, int mode, size_t size);
int fputs_native(const char *s, FILE *stream);
int fputc_native(int c, FILE *stream);
int ungetc_native(int c, FILE *stream);
ssize_t getdelim_native(char **lineptr, size_t *n, int delim, FILE *stream);
int vfscanf_native(FILE *stream, const char *format, va_list ap);

void closefrom_native(int low_fd);
int close_range_native(unsigned int low_fd, unsigned int max_fd, unsigned int flags);

#endif //NETFUZZLIB_NATIVE_H
