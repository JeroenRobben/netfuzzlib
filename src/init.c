#include <stdlib.h>

#include "netfuzzlib/callbacks.h"
#include "core/interfaces.h"
#include "core/network_env.h"

// Priority 101 = highest legal user-defined ctor priority.
__attribute__((constructor(101)))
void nfl_initialize() {
    nfl_init_logging(getenv("NETWORK_LOG_FILE"));

    int err = init_main_library();

    if (err) {
        nfl_die(1, "Error initializing network environment.");
    }
    if (!nfl_setup) {
        nfl_die(1, "Function nfl_setup() was not linked, probably no module is present in the linker path.");
    }
    nfl_log("Initializing fuzzing module");
    err = nfl_setup();
    if (err) {
        nfl_die(1, "Error initializing fuzzing module.");
    }

    // Mirror the host's network devices if no devices were configured during nfl_setup.
    if (!env_has_non_loopback_iface()) {
        nfl_import_host_network_devices();
    }
}
