#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include "network_env.h"
#include "import_host.h"
#include "hooks/hooks.h"
#include "interfaces.h"

int init_main_library() {
    char *env_enable_import_host_network_devices = getenv("ENABLE_IMPORT_HOST_NETWORK_DEVICES");

    bool enable_import_host_network_devices = env_enable_import_host_network_devices && strcmp(env_enable_import_host_network_devices, "0") != 0;
    bool autogen_loopback_device = !getenv("DISABLE_LOOPBACK_DEVICE_AUTOGEN");
    bool autogen_ipv6_link_local = !getenv("DISABLE_IPV6_LINK_LOCAL_AUTOGEN");

    nfl_log_info("Network environment configuration:, ENABLE_IMPORT_HOST_NETWORK_DEVICES: %d, DISABLE_LOOPBACK_DEVICE_AUTOGEN: %d,"
                 "DISABLE_IPV6_LINK_LOCAL_AUTOGEN: %d",
                 enable_import_host_network_devices, !autogen_loopback_device, !autogen_ipv6_link_local);
    network_env *env = get_network_env();
    memset(env, 0, sizeof(network_env));
    nfl_set_free_pkts(true);

    if (autogen_loopback_device) {
        if (enable_import_host_network_devices) {
            nfl_log_info("Skipping automatic adding lo device since importing host network l2_interfaces is enabled.");
        } else {
            add_loopback_device();
        }
    }
    if (enable_import_host_network_devices) {
        import_host_network_devices();
    }

    liveness_ctr_clear();
    int fd_dev_null = open("/dev/null", O_RDONLY);
    if (fd_dev_null < 0) {
        nfl_log_error("Could not open /dev/null");
        return -1;
    }
    env->fd_dev_null = dup2_native(fd_dev_null, NFL_FD_DEV_NULL);
    close_native(fd_dev_null);
    if (env->fd_dev_null < 0) {
        nfl_log_error("Could not dup2 /dev/null");
        return -1;
    }
    return 0;
}

void nfl_set_free_pkts(bool free_enabled) {
    get_network_env()->enable_packet_free = free_enabled;
}

inline network_env *get_network_env() {
    static network_env network_env = { 0 };
    return &network_env;
}
