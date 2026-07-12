#ifndef NETFUZZLIB_IOCTL_H
#define NETFUZZLIB_IOCTL_H

#include "network_types.h"

int ioctl_nfl(nfl_sock_full_t *sock, unsigned long request, void *argp);

#endif // NETFUZZLIB_IOCTL_H
