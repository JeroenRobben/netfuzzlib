#include <fcntl.h>
#include <string.h>
#include "interfaces.h"
#include "callback_wrapper.h"
#include "interceptors/native.h"
#include "network_env.h"

int init_main_library() {
    network_env *env = get_network_env();
    memset(env, 0, sizeof(network_env));

    add_loopback_device();

    const int fd_dev_null = open("/dev/null", O_RDONLY);
    if (fd_dev_null < 0) {
        nfl_log("Could not open /dev/null");
        return -1;
    }
    env->fd_dev_null = dup2_native(fd_dev_null, NFL_FD_DEV_NULL);
    close_native(fd_dev_null);
    if (env->fd_dev_null < 0) {
        nfl_log("Could not dup2 /dev/null");
        return -1;
    }
    return 0;
}

inline network_env *get_network_env() {
    static network_env network_env = { NULL };
    return &network_env;
}
