enable_language(CXX)
set(CMAKE_CXX_STANDARD 17)

include(FetchContent)
FetchContent_Declare(googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG f8d7d77c06936315286eb55f8de22cd23c188571 # v1.14.0
        FIND_PACKAGE_ARGS NAMES GTest)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

# Test module: a minimal nfl module that publishes a deterministic interface
# set so tests have a known ground truth in nfl mode.
add_subdirectory(modules)

# Integration tests: vanilla network programs driven by LD_PRELOAD + a
# scripted module that asserts traffic against a scenario file.
add_subdirectory(integration)

# Sources shared by both the native and the nfl test binaries.
set(NFL_TEST_SOURCES
        common/test_helpers.cpp
        unit/infra_test.cpp
        unit/socket_test.cpp
        unit/bind_test.cpp
        unit/connect_test.cpp
        unit/listen_accept_test.cpp
        unit/shutdown_test.cpp
        unit/close_test.cpp
        unit/dup_test.cpp
        unit/sockopt_test.cpp
        unit/fcntl_test.cpp
        unit/ioctl_test.cpp
        unit/poll_select_test.cpp
        unit/liveness_test.cpp
        unit/getifaddrs_test.cpp
        unit/netlink_test.cpp
        unit/udp_io_test.cpp
        unit/epoll_test.cpp
        unit/epoll_semantics_test.cpp
        unit/fd_pool_test.cpp
        unit/resolver_test.cpp
        unit/import_host_test.cpp
        unit/routing_test.cpp
        unit/tcp_io_test.cpp
        unit/stdio_test.cpp
        unit/util_test.cpp)

# tests_native: runs against the real Linux kernel via libc.
# A test that fails here is wrong about the spec — fix the test.
add_executable(tests_native ${NFL_TEST_SOURCES})
target_include_directories(tests_native PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
target_compile_definitions(tests_native PRIVATE NFL_TEST_NATIVE_MODE)
target_link_libraries(tests_native PRIVATE GTest::gtest_main)
gtest_discover_tests(tests_native
        TEST_PREFIX "native."
        PROPERTIES LABELS "native")

# tests_nfl: same source, linked against libnfl. The interceptors in
# libnfl redirect libc socket calls into the model. Same spec test that
# passed against the kernel must also pass here.
#
# The test module is loaded as a real shared object (libmodule-test.so), not
# statically linked, so it mirrors the LD_PRELOAD deployment: the framework
# resolves module callbacks via dlsym(RTLD_NEXT, ...) — which only finds the
# module when it lives in a separate object loaded after netfuzzlib.
#   - netfuzzlib_static is whole-archived so its entire library API (nfl_alloc_pkt,
#     iov_count_bytes, …) lands in the executable, and ENABLE_EXPORTS puts those
#     symbols in the dynamic table so libmodule-test.so resolves them at load.
#   - netfuzzlib's undefined module callbacks (nfl_receive, nfl_tcp_accept, …)
#     are satisfied at link time by libmodule-test.so's exports.
add_executable(tests_nfl ${NFL_TEST_SOURCES})
target_include_directories(tests_nfl PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/common)
target_compile_definitions(tests_nfl PRIVATE NFL_TEST_NFL_MODE)
set_target_properties(tests_nfl PROPERTIES ENABLE_EXPORTS ON)
target_link_libraries(tests_nfl PRIVATE
        GTest::gtest_main
        -Wl,--whole-archive netfuzzlib_static -Wl,--no-whole-archive
        module-test
        ${CMAKE_DL_LIBS})
gtest_discover_tests(tests_nfl
        TEST_PREFIX "nfl."
        PROPERTIES
                LABELS "nfl"
                # Debug builds compile in nfl_log; send it to /dev/null so test
                # output stays clean (there is no log-level knob any more).
                ENVIRONMENT "NETWORK_LOG_FILE=/dev/null")
