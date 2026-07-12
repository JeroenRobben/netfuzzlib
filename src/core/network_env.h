#ifndef NETFUZZLIB_NETWORK_ENV_H
#define NETFUZZLIB_NETWORK_ENV_H

#include "network_types.h"

#define NFL_FD_DEV_NULL NFL_RESERVED_FD_START
#define NFL_FD_LOG (NFL_RESERVED_FD_START + 1)

/**
 * Initialize the netfuzzlib main library
 * @return 0 on success, -1 on failure
 */
int init_main_library();

/**
 * Get the current global network environment
 */
network_env *get_network_env();

#endif // NETFUZZLIB_NETWORK_ENV_H
