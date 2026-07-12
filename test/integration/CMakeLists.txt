# Integration tests live in two self-contained subdirs:
#
#   cases/     bash-driven black-box tests. Each case is a directory under
#              cases/ with `cmd`, optional `scenario.txt`, optional
#              `stdout.expected`. See cases/run_case.sh for the contract.
#   docker/    docker-isolated tests: real network daemons (lighttpd,
#              redis, kamailio, …) and small C SUT programs driven by the
#              scripted module. See docker/CMakeLists.txt.
#
# The scripted nfl module (module-test-scripted) is built in test/modules/
# alongside the unit-test module, not here.

# Under ASan, the runtime must be the FIRST entry in LD_PRELOAD. Otherwise it
# trips its "not first" check the moment another preload pulls in an ASan-
# instrumented symbol. The runtime's filename differs between toolchains:
# gcc ships libasan.so, clang ships libclang_rt.asan-<arch>.so (and only
# resolves it via -print-file-name when -shared-libasan is in effect, see the
# top-level CMakeLists).
set(NFL_INTEGRATION_PRELOAD_PREFIX "")
if(NFL_ASAN)
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} -print-file-name=libclang_rt.asan-${CMAKE_SYSTEM_PROCESSOR}.so
            OUTPUT_VARIABLE NFL_LIBASAN_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    else()
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} -print-file-name=libasan.so
            OUTPUT_VARIABLE NFL_LIBASAN_PATH
            OUTPUT_STRIP_TRAILING_WHITESPACE)
    endif()
    if(NFL_LIBASAN_PATH AND EXISTS "${NFL_LIBASAN_PATH}")
        set(NFL_INTEGRATION_PRELOAD_PREFIX "${NFL_LIBASAN_PATH}:")
    else()
        message(WARNING "NFL_ASAN=ON but ASan runtime not found via "
                "${CMAKE_C_COMPILER} -print-file-name; integration tests will "
                "likely fail with 'incompatible ASan runtimes'. Found: '${NFL_LIBASAN_PATH}'")
    endif()
endif()

# === cases/: bash-driven case tests ===
# Each subdir is one test:
#   cases/<name>/cmd                   bash pipeline (may use $NFL_LD_PRELOAD)
#   cases/<name>/scenario.txt          optional, drives the scripted module
#   cases/<name>/stdout.expected       optional, regex-per-line stdout match
function(nfl_register_case_dir CASE_DIR)
    get_filename_component(CASE_NAME "${CASE_DIR}" NAME)
    add_test(NAME integration.${CASE_NAME}
             COMMAND ${CMAKE_COMMAND} -E env
                     "NFL_LD_PRELOAD=${NFL_INTEGRATION_PRELOAD_PREFIX}$<TARGET_FILE:netfuzzlib>:$<TARGET_FILE:module-test-scripted>"
                     bash "${CMAKE_CURRENT_SOURCE_DIR}/cases/run_case.sh" "${CASE_DIR}")
    set_tests_properties(integration.${CASE_NAME} PROPERTIES
            LABELS "integration"
            TIMEOUT 30)
endfunction()

# Tool-availability gates by case-name prefix. `nc` must be the OpenBSD
# variant (gnu-netcat lacks -W and -q). Skip silently when absent.
find_program(NC_BIN nc)
if(NC_BIN)
    execute_process(COMMAND ${NC_BIN} -h
                    OUTPUT_VARIABLE NC_HELP_OUT
                    ERROR_VARIABLE NC_HELP_OUT
                    OUTPUT_STRIP_TRAILING_WHITESPACE)
    if(NOT NC_HELP_OUT MATCHES "OpenBSD netcat")
        message(STATUS "Skipping nc integration tests: ${NC_BIN} is not OpenBSD netcat")
        set(NC_BIN "")
    endif()
endif()

file(GLOB _integration_case_dirs RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/cases"
     "${CMAKE_CURRENT_SOURCE_DIR}/cases/*")
foreach(_case_name ${_integration_case_dirs})
    set(_case_path "${CMAKE_CURRENT_SOURCE_DIR}/cases/${_case_name}")
    if(NOT IS_DIRECTORY "${_case_path}")
        continue()
    endif()
    if(_case_name MATCHES "^nc_" AND NOT NC_BIN)
        message(STATUS "Skipping integration.${_case_name}: nc not available")
        continue()
    endif()
    if(_case_name MATCHES "^ifconfig_")
        find_program(IFCONFIG_BIN ifconfig)
        if(NOT IFCONFIG_BIN)
            message(STATUS "Skipping integration.${_case_name}: ifconfig not installed")
            continue()
        endif()
    endif()
    if(_case_name MATCHES "^telnet_")
        find_program(TELNET_BIN telnet)
        if(NOT TELNET_BIN)
            message(STATUS "Skipping integration.${_case_name}: telnet not installed")
            continue()
        endif()
    endif()
    if(_case_name MATCHES "^ip_")
        find_program(IP_BIN ip)
        if(NOT IP_BIN)
            message(STATUS "Skipping integration.${_case_name}: ip (iproute2) not installed")
            continue()
        endif()
    endif()
    nfl_register_case_dir("${_case_path}")
endforeach()

# === docker/: docker-isolated daemons + program SUTs ===
add_subdirectory(docker)
