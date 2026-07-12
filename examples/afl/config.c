#include "config.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>

#include <netfuzzlib/api.h>
#include <netfuzzlib/log.h>

afl_module_config *afl_get_config(void) {
    static afl_module_config cfg;
    return &cfg;
}

int afl_load_config(void) {
    afl_module_config *cfg = afl_get_config();

    const char *port_str = getenv("NFL_PORT");
    if (!port_str) {
        nfl_log("NFL_PORT not set");
        return -1;
    }
    int port = (int)strtol(port_str, NULL, 10);
    if (port <= 0 || port > 65535) {
        nfl_log("NFL_PORT invalid (got %s)", port_str);
        return -1;
    }
    cfg->sut_port_net = htons((uint16_t)port);
    return 0;
}
