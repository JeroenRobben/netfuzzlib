#ifndef MODULE_AFL_CONFIG_H
#define MODULE_AFL_CONFIG_H
#include <netinet/in.h>
#include <stdbool.h>
#include <netfuzzlib/api.h>

enum tcp_mode { SUT_IS_CLIENT = 1, SUT_IS_SERVER = 0 };

typedef struct afl_module_config {
    uint32_t protocol;
    nfl_addr_t addr_fuzzer;
    nfl_addr_t addr_sut;
    enum tcp_mode tcp_mode;
    bool stop_fuzzing;
    bool persistent_mode;

} afl_module_config;

afl_module_config *get_module_config();
nfl_pkt *get_static_packet();

int load_config();
int load_config_ip_sut();
int load_config_ipv4(int sut_port);
int load_config_ipv6(int sut_port);

#endif //MODULE_AFL_CONFIG_H
