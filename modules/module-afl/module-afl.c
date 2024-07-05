#pragma clang diagnostic push
#pragma ide diagnostic ignored "bugprone-reserved-identifier"
#include "module-afl.h"
#include "module-afl-config.h"
#include "netfuzzlib/util.h"
#include "wait-child.h"
#include "hooks/native.h"
#include <netfuzzlib/module_api.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/wait.h>
#include <string.h>
#include <dirent.h>
#include <dlfcn.h>

#define AFL_PERSISTENT_LOOP_COUNT 1000


extern int __afl_sharedmem_fuzzing;
extern unsigned int *__afl_fuzz_len;
extern unsigned char *__afl_fuzz_ptr;

static int dummy_prefix_packets_count = 0;
static bool wait_for_child = false;

void set_stop_fuzzing(bool stop_fuzzing) {
    nfl_log_debug("netfuzzlib_afl set_stop_fuzzing: %b", stop_fuzzing);
    get_module_config()->stop_fuzzing = stop_fuzzing;
}

int attach_afl_shmem() {
//    if (!__afl_fuzz_ptr) {
//        nfl_log_debug("attaching shmem");
//        char *id_str = getenv("__AFL_SHM_FUZZ_ID");
//        if (!id_str) {
//            nfl_log_fatal("AFL-module-initialize: %s not set", "SHM_FUZZ_ENV_VAR");
//            return -1;
//        }
//        int shm_id = atoi(id_str);
//        uint8_t *map = (uint8_t *)shmat(shm_id, NULL, 0);
//        if (!map || map == (void *)-1) {
//            nfl_log_fatal("AFL-module-initialize: shmat failed");
//            return -1;
//        }
//        __afl_fuzz_len = (uint32_t *)map;
//        __afl_fuzz_ptr = map + sizeof(uint32_t);
//    }
//
//    if(__afl_fuzz_ptr_ptr == NULL || __afl_fuzz_len_ptr == NULL || __afl_sharedmem_fuzzing_ptr == NULL) {
//        __afl_fuzz_ptr_ptr = dlsym(RTLD_DEFAULT, "__afl_fuzz_ptr");
//        if(!__afl_fuzz_ptr_ptr) {
//            nfl_log_fatal("AFL-module-initialize: __afl_fuzz_ptr_ptr not set");
//            return -1;
//        }
//
//        __afl_fuzz_len_ptr = dlsym(RTLD_DEFAULT, "__afl_fuzz_len");
//        if(!__afl_fuzz_len_ptr) {
//            nfl_log_fatal("AFL-module-initialize: __afl_fuzz_len_ptr not set");
//            return -1;
//        }
//
//        __afl_sharedmem_fuzzing_ptr = dlsym(RTLD_DEFAULT, "__afl_sharedmem_fuzzing");
//        if(!__afl_sharedmem_fuzzing_ptr) {
//            nfl_log_fatal("AFL-module-initialize: __afl_sharedmem_fuzzing_ptr not set");
//            return -1;
//        }
//        *__afl_sharedmem_fuzzing_ptr = 1;
//    }
    return 0;
}

void clear_dicom() {
    // These are data types defined in the "dirent" header
    char *path = "/home/jeroen/afl-nfl/dcmtk-afl/build/bin/ACME_STORE";
    DIR *const directory = opendir(path);
    if (!directory)
        return;

    struct dirent *entry;
    while ((entry = readdir(directory))) {
        if (!strcmp(".", entry->d_name) || !strcmp("..", entry->d_name)) {
            continue;
        }
        char filename[strlen(path) + strlen(entry->d_name) + 2];
        sprintf(filename, "%s/%s", path, entry->d_name);
        if (entry->d_type == DT_DIR)
            continue;
        remove(filename);
    }
    closedir(directory);
}

/**
 * Initialize this module, called once during environment setup.
 * Usually adding network interfaces happens here.
 */
int nfl_initialize() {
    nfl_log_debug("AFL-module-initialize");
    nfl_set_free_pkts(false); //Shouldn't call free on __AFL_FUZZ_TESTCASE_BUF
    memset(get_module_config(), 0, sizeof(afl_module_config));

    if (load_config() != 0) {
        nfl_log_fatal("AFL-module-initialize load config failed");
        return -1;
    }

    dummy_prefix_packets_count = 0;
    if (getenv("NFL_AFL_DUMMY_PREFIX_PACKETS_COUNT")) {
        dummy_prefix_packets_count = atoi(getenv("NFL_AFL_DUMMY_PREFIX_PACKETS_COUNT"));
    }
    if(getenv("NFL_AFL_WAIT_FOR_CHILD")) {
        wait_for_child = true;
    }

    set_stop_fuzzing(false);

    attach_afl_shmem();
    nfl_log_debug("nfl_initialize: __afl_fuzz_ptr: %p\n", __afl_fuzz_ptr);
    if (getenv("DCMDICTPATH"))
        clear_dicom();
    __afl_sharedmem_fuzzing = 1;
//    init_wait_child();
    return 0;
}

/**
 * Define whether an attempted outgoing tcp connection should succeed
 * Parameters local_addr and remote_addr are guaranteed to be of same type, sockaddr_in or sockaddr_in6
 * @param local_addr The local address of the sock in case the connect would be successful.
 * @param remote_addr The remote address of the attempted connection.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_connect(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, const nfl_addr_t *remote_addr) {
    return false;
}

/**
 * Define an incoming tcp connection. Called when an application invokes 'accept' on a listening sock.
 * Parameters local_addr and remote_addr are guaranteed to be of same type, sockaddr_in or sockaddr_in6
 * @param local_addr The local address bound to the sock.
 * @param remote_addr The address of the remote endpoint. This must be initialized by the module in case the connection was successful.
 * @return True on successful connection, false otherwise.
 */
bool nfl_tcp_accept(const nfl_sock_module_t *sock, const nfl_addr_t *local_addr, nfl_addr_t *remote_addr) {
    static int amount_accepted = 0;
    if (get_module_config()->protocol != IPPROTO_TCP)
        return false;
    if (get_module_config()->stop_fuzzing)
        return false;
    if (!ip_endpoints_match(local_addr, &get_module_config()->addr_sut))
        return false;

    if(wait_for_child) {
//        set_track_child_pids(true);
//        wait_child_thread();
    }

    if (get_module_config()->persistent_mode) {
        if (!(__afl_persistent_loop(AFL_PERSISTENT_LOOP_COUNT))) {
            set_stop_fuzzing(true);
            return false;
        }
    } else {
        if (amount_accepted > 0)
            return false;
        amount_accepted++;
    }
    nfl_log_debug("AFL-module-tcp-accept success, amount_accepted: %d", amount_accepted);
    memcpy(remote_addr, &get_module_config()->addr_fuzzer.s4, get_socket_domain_addrlen(sock->domain));
    return true;
}

/**
 * Called when an application attempts to send data on a network sock
 * @param sock The sock on which a send call was issued
 * @param from The sender address of the packet, type sockaddr_in | sockaddr_in6
 * @param to The destination address of the packet, type sockaddr_in | sockaddr_in6
 * @param iov Array of iovec structs containing the outgoing data
 * @param iovlen The amount of iovec structs in the array
 * @return The amount of bytes sent, or a negative value in case of an error
 */
ssize_t nfl_send(const nfl_sock_module_t *sock, const nfl_addr_t *from, const nfl_addr_t *to, struct iovec *iov, size_t iovlen) {
    return iov_count_bytes(iov, iovlen);
}

void __afl_manual_init(void);

nfl_pkt *nfl_receive(const nfl_sock_module_t *sock, const nfl_addr_t *bound_addr) {
    nfl_log_debug("nfl_receive: __afl_fuzz_ptr: %p\n", __afl_fuzz_ptr);
    nfl_log_debug("MODULE RECEIVE AFL, stop fuzzing: %b", get_module_config()->stop_fuzzing);
    if (sock->protocol != get_module_config()->protocol)
        return NULL;
    if (get_module_config()->stop_fuzzing)
        return NULL;
    nfl_log_debug("MODULE RECEIVE AFL: checking ip endpoints...");
    if (get_module_config()->protocol != IPPROTO_TCP && !ip_endpoints_match(bound_addr, &get_module_config()->addr_sut))
        return NULL;
    nfl_log_debug("MODULE RECEIVE AFL: checking ip endpoints...match");

    if (dummy_prefix_packets_count > 0) {
        dummy_prefix_packets_count--;
        nfl_log_info("AFL: sending empty prefix packet, dummy packets left: %d", dummy_prefix_packets_count);
        return NULL;
    }

    if (get_module_config()->persistent_mode) {
        if (get_module_config()->protocol != IPPROTO_TCP && (!(__afl_persistent_loop(AFL_PERSISTENT_LOOP_COUNT)))) {
            set_stop_fuzzing(true);
            nfl_log_debug("afl persistent loop stop");
            return NULL;
        }
    } else {
        set_stop_fuzzing(true); // We only have one packet
//        __afl_manual_init();
    }

    if (get_module_config()->protocol != IPPROTO_TCP) {
        memcpy(&get_static_packet()->remote_addr, &get_module_config()->addr_fuzzer.s, get_socket_domain_addrlen(get_module_config()->addr_sut.s.sa_family));
        memcpy(&get_static_packet()->local_addr, &get_module_config()->addr_sut.s, get_socket_domain_addrlen(get_module_config()->addr_sut.s.sa_family));
    }

    get_static_packet()->iov.iov_base = __afl_fuzz_ptr;
    get_static_packet()->iov.iov_len = *__afl_fuzz_len;
    get_static_packet()->device_index = 1;

    nfl_log_debug("MODULE RECEIVE AFL: returned packet, len: %d", get_static_packet()->iov.iov_len);
    return get_static_packet();
}
#pragma clang diagnostic pop