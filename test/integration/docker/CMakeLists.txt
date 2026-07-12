# Docker-isolated integration tests. Two flavours of target live here:
#
#   - **Daemon targets** (lighttpd, redis, kamailio, …): a real network
#     daemon runs inside the container with libnfl + the kernel-
#     bridge module LD_PRELOAD'd, and a real protocol client (curl,
#     dig, redis-cli, …) drives it.
#   - **Program target** (`programs`): one image with all the small
#     SUT-style C programs in src/ pre-built. CTest entries dispatch
#     to a specific binary + scenario via env vars. The scripted module
#     replays the canned traffic and asserts the SUT's outbound bytes
#     match.
#
# Skipped silently when docker is not on PATH. Otherwise one CTest entry
# per registered test. All entries are labelled both `integration` and
# `docker` so they can be run/excluded as a group:
#
#   ctest -L docker            # only this suite
#   ctest -LE docker           # everything except this suite
#
# Per-target files: <name>/Dockerfile + <name>/run.sh.

find_program(DOCKER_BIN docker)
if(NOT DOCKER_BIN)
    message(STATUS "docker not found — docker-based integration tests will be skipped. "
                   "Install Docker and re-run cmake to enable them.")
    return()
endif()

set(NFL_DOCKER_BUILD_CONTEXT "${CMAKE_SOURCE_DIR}")
set(NFL_DOCKER_BASE_TAG "netfuzzlib-base")
set(NFL_DOCKER_BASE_DOCKERFILE "${CMAKE_CURRENT_SOURCE_DIR}/Dockerfile.base")
# Where the host's compiled libs live. run-target.sh bind-mounts this
# into each container so source-only edits don't trigger a Docker
# rebuild. See run-target.sh / Dockerfile.base for the rationale.
set(NFL_DOCKER_HOST_LIB_DIR "${CMAKE_BINARY_DIR}/lib")

# Register a CTest entry that builds the named target image (lazily,
# layer-cache friendly) and runs it once. Optional ARGN is forwarded as
# KEY=VAL pairs through to `docker run -e`, used by the programs target
# to select binary + scenario per ctest entry.
function(nfl_register_docker_test TEST_NAME TARGET_DIR)
    set(_image "netfuzzlib-test-${TARGET_DIR}")
    set(_dockerfile "${CMAKE_CURRENT_SOURCE_DIR}/${TARGET_DIR}/Dockerfile")
    if(NOT EXISTS "${_dockerfile}")
        message(WARNING "Docker target '${TARGET_DIR}' missing ${_dockerfile} — skipping ${TEST_NAME}")
        return()
    endif()
    add_test(NAME integration.docker.${TEST_NAME}
             COMMAND bash "${CMAKE_CURRENT_SOURCE_DIR}/run-target.sh"
                     "${TARGET_DIR}"
                     "${NFL_DOCKER_BUILD_CONTEXT}"
                     "${NFL_DOCKER_BASE_DOCKERFILE}"
                     "${NFL_DOCKER_BASE_TAG}"
                     "${_dockerfile}"
                     "${_image}"
                     "${NFL_DOCKER_HOST_LIB_DIR}"
                     ${ARGN})
    # 60 s: warm-cache run is ~5–25 s per target. Cold base build for
    # heavy apt-get / source-build steps adds ~10–15 s on first run.
    set_tests_properties(integration.docker.${TEST_NAME} PROPERTIES
            LABELS "integration;docker"
            TIMEOUT 60)
endfunction()

# Convenience wrapper: 1:1 daemon target ↔ ctest entry.
function(nfl_register_docker_target NAME)
    nfl_register_docker_test("${NAME}" "${NAME}")
endfunction()

# === Daemon targets ===
# Add new targets by dropping a `<name>/Dockerfile` and `<name>/run.sh`
# in this directory and listing the name here.
nfl_register_docker_target(lightftp)
nfl_register_docker_target(bftpd)
nfl_register_docker_target(dnsmasq)
nfl_register_docker_target(openssl)
nfl_register_docker_target(ssh-keyscan)
nfl_register_docker_target(live555)
nfl_register_docker_target(exim)
nfl_register_docker_target(proftpd)
nfl_register_docker_target(pure-ftpd)
nfl_register_docker_target(tinydtls)
nfl_register_docker_target(tinydtls-client)
nfl_register_docker_target(kamailio)
nfl_register_docker_target(lighttpd)
nfl_register_docker_target(mosquitto)
nfl_register_docker_target(snmpd)
nfl_register_docker_target(rsyslog)
nfl_register_docker_target(rsync)
nfl_register_docker_target(memcached)
nfl_register_docker_target(redis)
nfl_register_docker_target(libcoap)
# AFL module's accept+fork-per-conn child-pid tracker, self-contained,
# no external client. See afl-fork/Dockerfile.
nfl_register_docker_target(afl-fork)
# Real AFL run: afl-fuzz drives an instrumented target under
# AFL_PRELOAD=libnfl+libnfl-afl. Pass = at least one crash
# file in the AFL output corpus inside the time budget.
nfl_register_docker_target(afl-real)
if(TEST integration.docker.afl-real)
    # 180 s fuzzing budget + apt-install afl++ on cold cache.
    set_tests_properties(integration.docker.afl-real PROPERTIES TIMEOUT 360)
endif()
# Real-daemon AFL smoke targets: afl-clang-fast'd build of an upstream
# daemon, fuzzed for ~60 s. Pass = AFL ran cleanly and grew its corpus
# (proves fuzz bytes reach the SUT and exercise new edges). Finding an
# actual crash on a hardened daemon needs a far longer budget.
nfl_register_docker_target(afl-dnsmasq)
if(TEST integration.docker.afl-dnsmasq)
    # 60 s fuzz + cold-cache wget+make of dnsmasq + apt-install afl++.
    set_tests_properties(integration.docker.afl-dnsmasq PROPERTIES TIMEOUT 360)
endif()
nfl_register_docker_target(afl-redis)
if(TEST integration.docker.afl-redis)
    # 60 s fuzz + cold-cache redis tarball + make.
    set_tests_properties(integration.docker.afl-redis PROPERTIES TIMEOUT 600)
endif()
nfl_register_docker_target(afl-curl)
if(TEST integration.docker.afl-curl)
    # 60 s fuzz + cold-cache curl tarball + autotools configure + make.
    set_tests_properties(integration.docker.afl-curl PROPERTIES TIMEOUT 900)
endif()
# Same SUT-side pipeline as afl-dnsmasq, but the driver is a Rust
# binary built on libafl::executors::forkserver::ForkserverExecutor.
# Proves afl needs no changes for LibAFL's forkserver path.
nfl_register_docker_target(libafl-dnsmasq)
if(TEST integration.docker.libafl-dnsmasq)
    # Cold cache: ~5 min for `cargo build --release` of libafl + deps,
    # plus the usual apt-install afl++ and dnsmasq source build.
    # Warm cache: ~30 s fuzz budget only.
    set_tests_properties(integration.docker.libafl-dnsmasq PROPERTIES TIMEOUT 900)
endif()
# Cross-language servers. Does LD_PRELOAD interception reach them?
# Bailed: node-http (libuv timeout assertion), go-http (Go runtime issues
# raw syscalls, fully bypasses LD_PRELOAD). See NOTES.md.
nfl_register_docker_target(python-http)
nfl_register_docker_target(rust-http)
nfl_register_docker_target(java-http)
# curl as SUT (client side of the bridge), fetches from an unmodified
# python http.server in the same container.
nfl_register_docker_target(curl)

# Per-target timeout overrides
if(TEST integration.docker.live555)
    # Builds a sizeable C++ library from source on cold cache (a few
    # minutes on a fresh CI runner).
    set_tests_properties(integration.docker.live555 PROPERTIES TIMEOUT 600)
endif()
if(TEST integration.docker.java-http)
    # Cold-cache JDK install + javac compile is ~30 s.
    set_tests_properties(integration.docker.java-http PROPERTIES TIMEOUT 180)
endif()

# === Program targets (scripted-module SUT tests) ===
# One image (programs/) with all the small SUT-style C programs from
# programs/src/ pre-built. Each ctest entry below picks the binary and
# scenario via env vars. See programs/Dockerfile + programs/run.sh.
function(nfl_register_program TEST_NAME PROGRAM SCENARIO)
    set(_extra "")
    if(ARGC GREATER 3)
        list(APPEND _extra "NFL_BACKEND=${ARGV3}")
    endif()
    nfl_register_docker_test("${TEST_NAME}" programs
            "NFL_PROGRAM=${PROGRAM}"
            "NFL_SCENARIO=${SCENARIO}"
            ${_extra})
endfunction()

nfl_register_program(udp_echo           udp_echo           udp_echo.txt)
nfl_register_program(http_get_responder http_get_responder http_get.txt)

# libevent + libev each support three I/O backends. Force each in turn so a
# regression that only affects one backend can't hide behind the others.
foreach(_backend epoll poll select)
    nfl_register_program(libevent_udp_echo_${_backend}
                         libevent_udp_echo udp_echo.txt ${_backend})
    nfl_register_program(libevent_http_responder_${_backend}
                         libevent_http_responder http_get.txt ${_backend})
    nfl_register_program(libev_udp_echo_${_backend}
                         libev_udp_echo udp_echo.txt ${_backend})
    nfl_register_program(libev_http_responder_${_backend}
                         libev_http_responder http_get.txt ${_backend})
endforeach()

# Threaded libevent forces an internal eventfd onto the epoll instance.
# libuv registers an internal eventfd on the loop's epoll. Both pass
# thanks to the hybrid epoll (split-and-merge in src/core/epoll.c).
nfl_register_program(libevent_threaded_udp_echo
                     libevent_threaded_udp_echo udp_echo.txt)
nfl_register_program(libuv_udp_echo        libuv_udp_echo        udp_echo.txt)
nfl_register_program(libuv_http_responder  libuv_http_responder  http_get.txt)

# === Per-PR smoke subset ===
# A handful of targets (one per major code path) also carry the
# `integration-pr` label, so a PR that touches the model surface can run a
# quick gate (`ctest -L integration-pr`) without paying for the full
# nightly suite. Keep this list short and fast: skip the long cold-build
# daemons (live555, java-http) and the multi-minute afl-* fuzz runs.
# integration-docker.yml's per-PR matrix mirrors the daemon entries here.
# Keep the two in sync.
function(nfl_mark_pr_subset)
    foreach(_name ${ARGN})
        set(_test "integration.docker.${_name}")
        if(NOT TEST "${_test}")
            message(WARNING "nfl_mark_pr_subset: no test '${_test}' "
                            "(missing Dockerfile, or name typo?) — not labelled integration-pr")
            continue()
        endif()
        get_test_property("${_test}" LABELS _labels)
        set_tests_properties("${_test}" PROPERTIES LABELS "${_labels};integration-pr")
    endforeach()
endfunction()

nfl_mark_pr_subset(
    lightftp                       # BSD-style FTP daemon (accept loop, sockopts)
    lighttpd                       # HTTP daemon
    dnsmasq                        # UDP DNS daemon
    openssl                        # TLS handshake over the model
    redis                          # epoll-driven event loop
    libevent_http_responder_epoll  # scripted-module SUT + libevent backend
)
