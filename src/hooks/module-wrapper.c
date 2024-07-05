#include <dlfcn.h>
#include "netfuzzlib/module_api.h"

void nfl_end_priv() {
    static void (*nfl_end_module)() = NULL;
    if (!nfl_end_module)
        nfl_end_module = dlsym(RTLD_NEXT, "nfl_end");
    if (nfl_end_module) {
        (*nfl_end_module)();
    }
    exit(0);
}