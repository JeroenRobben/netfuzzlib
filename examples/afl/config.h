#ifndef MODULE_AFL_CONFIG_H
#define MODULE_AFL_CONFIG_H

#include <stdbool.h>
#include <stdint.h>

typedef struct afl_module_config {
    /* Port the SUT binds/listens/connects to (NFL_PORT), network byte order. */
    uint16_t sut_port_net;
    bool stop_fuzzing; /* latched after the single testcase is delivered */
} afl_module_config;

afl_module_config *afl_get_config(void);

int afl_load_config(void);

#endif // MODULE_AFL_CONFIG_H
