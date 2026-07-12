#ifndef NETFUZZLIB_EPOLL_H
#define NETFUZZLIB_EPOLL_H

#include "network_types.h"
#include <signal.h>
#include <sys/epoll.h>
#include <time.h>

int epoll_create_nfl(int size);
int epoll_create1_nfl(int flags);
int epoll_ctl_nfl(nfl_sock_full_t *epoll_sock, int op, int fd, struct epoll_event *event);
int epoll_wait_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events,
                   int maxevents, int timeout);
int epoll_pwait_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events,
                    int maxevents, int timeout, const sigset_t *sigmask);
int epoll_pwait2_nfl(nfl_sock_full_t *epoll_sock, struct epoll_event *events,
                     int maxevents, const struct timespec *timeout,
                     const sigset_t *sigmask);

void epoll_free(nfl_epoll_t *ep);

void epoll_detach_watches_on(nfl_sock_full_t *sock);

#endif // NETFUZZLIB_EPOLL_H
