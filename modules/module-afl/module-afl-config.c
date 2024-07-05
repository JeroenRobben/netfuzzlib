#include <stddef.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include "module-afl-config.h"

afl_module_config *get_module_config() {
    static afl_module_config module_config;
    return &module_config;
}

static nfl_pkt *static_packet = NULL;

nfl_pkt *get_static_packet() {
    return static_packet;
}

int load_config_ipv6(int sut_port) {
    static_packet = nfl_alloc_pkt(0);
    if (!static_packet) {
        nfl_log_error("Failed to allocate static packet");
        return -1;
    }
    inet_pton(AF_INET6, "::1", &get_module_config()->addr_sut.s6.sin6_addr);
    get_module_config()->addr_sut.s6.sin6_family = AF_INET6;
    get_module_config()->addr_sut.s6.sin6_port = htons(sut_port);

    inet_pton(AF_INET6, "::1", &get_module_config()->addr_fuzzer.s6.sin6_addr);
    get_module_config()->addr_fuzzer.s6.sin6_family = AF_INET6;
    get_module_config()->addr_fuzzer.s6.sin6_port = htons(1234);
    return 0;
}

int load_config_ipv4(int sut_port) {
    static_packet = nfl_alloc_pkt(0);
    if (!static_packet) {
        nfl_log_error("Failed to allocate static packet");
        return -1;
    }
    inet_pton(AF_INET, "127.0.0.1", &get_module_config()->addr_sut.s4.sin_addr);
    get_module_config()->addr_sut.s4.sin_family = AF_INET;
    get_module_config()->addr_sut.s4.sin_port = htons(sut_port);

    inet_pton(AF_INET, "127.0.0.1", &get_module_config()->addr_fuzzer.s4.sin_addr);
    get_module_config()->addr_fuzzer.s4.sin_family = AF_INET;
    get_module_config()->addr_fuzzer.s4.sin_port = htons(1234);
    return 0;
}

int load_config_ip_sut() {
    char *proto_str = getenv("NETFUZZLIB_AFL_PROTO");
    if (!proto_str) {
        nfl_log_error("NETFUZZLIB_AFL_PROTO not set");
        return -1;
    }
    if (strcmp(proto_str, "tcp") == 0) {
        get_module_config()->protocol = IPPROTO_TCP;
    } else if (strcmp(proto_str, "udp") == 0) {
        get_module_config()->protocol = IPPROTO_UDP;
    } else {
        nfl_log_error("NETFUZZLIB_AFL_PROTO must be either tcp or udp");
        return -1;
    }

    char *sut_port_str = getenv("NETFUZZLIB_AFL_PORT");
    if (!sut_port_str) {
        nfl_log_error("NETFUZZLIB_AFL_PORT not set");
        return -1;
    }
    int sut_port = atoi(sut_port_str);
    if (sut_port == 0) {
        nfl_log_error("NETFUZZLIB_AFL_PORT must be a valid sut_port number");
        return -1;
    }

    char *ip_version_str = getenv("NETFUZZLIB_AFL_IP_VERSION");
    if (!ip_version_str || strcmp(ip_version_str, "4") == 0) {
        nfl_log_info("NETFUZZLIB_AFL_IP_VERSION set to 4");
        return load_config_ipv4(sut_port);
    } else if (strcmp(ip_version_str, "6") == 0) {
        nfl_log_info("NETFUZZLIB_AFL_IP_VERSION set to 6");
        return load_config_ipv6(sut_port);
    } else {
        nfl_log_error("NETFUZZLIB_AFL_IP_VERSION must be either 4 or 6");
        return -1;
    }
}

int load_config() {
    get_module_config()->tcp_mode = SUT_IS_SERVER;

    char *persistent_mode_str = getenv("AFL_PERSISTENT");
    if (!persistent_mode_str) {
        nfl_log_info("AFL_PERSISTENT not set");
        get_module_config()->persistent_mode = false;
    } else {
        nfl_log_info("AFL_PERSISTENT set");
        get_module_config()->persistent_mode = true;
    }

    return load_config_ip_sut();
}