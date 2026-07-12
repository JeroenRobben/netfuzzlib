#ifndef NETFUZZLIB_GETIFADDRS_H
#define NETFUZZLIB_GETIFADDRS_H

#include <ifaddrs.h>

int getifaddrs_nfl(struct ifaddrs **ifap);
void freeifaddrs_nfl(struct ifaddrs *ifa);

#endif // NETFUZZLIB_GETIFADDRS_H
