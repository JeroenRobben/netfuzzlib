#include <dlfcn.h>
#include "netfuzzlib/module_api.h"
#include "environment/network_env.h"

#ifndef INITIALIZE_NETWORK_MODEL_MANUAL
void nfl_init_manual() __attribute__((constructor(0)));
#endif

void nfl_init_manual() {
    if (getenv("NETFUZZLIB_MANUAL_INIT")) {
        return;
    }
    nfl_init_logging(getenv("NETWORK_LOG_FILE"));

    int err = init_main_library();

    if (err) {
        nfl_exit_log(1, "Error initializing network environment.");
    }
#ifndef MODULE_STATIC_LINKED
    if (!dlsym(RTLD_DEFAULT, "nfl_initialize")) {
        nfl_exit_log(1, "Function nfl_initialize() was not linked, probably no module is present in the linker path.");
    }
#endif
    if (!getenv("NETWORK_MODEL_MODULE_MANUAL_INIT")) {
        nfl_log_debug("Initializing fuzzing module");
        err = nfl_initialize();
        if (err) {
            nfl_exit_log(1, "Error initializing fuzzing module.");
        }
    }
}
