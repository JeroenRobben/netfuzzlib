set(SRC_FILES
        init.c
        sockets/sockets.c
        sockets/sockets_dgram.c
        sockets/sockets_stream.c
        sockets/sockets_rtnetlink.c
        sockets/poll.c
        sockets/sockopt.c
        sockets/sockets_util.c
        sockets/dup.c
        sockets/stdio.c
        environment/network_env.c
        environment/ioctl.c
        environment/routing.c
        environment/getifaddrs.c
        environment/import_host.c
        environment/util.c
        lib/libnl/libnl.c
        lib/logger/log.c
        hooks/hooks.c
        hooks/hooks-poll.c
        hooks/module-wrapper.c
        hooks/hooks-stdio.c
        environment/interfaces.c
        environment/fd_table.c)

set_source_files_properties(
        hooks/hooks.c
        PROPERTIES
        COMPILE_FLAGS "-Wno-incompatible-pointer-types"
)

set(native-call-forwarder "libc" CACHE STRING
        "Specify how to forward native calls to the OS, possible values: syscall-x86-64 (directly invoke syscall, only valid for x86-64 architecture),
        libc (forward to native c standard library)")
set(possible-native-forwarders "libc;syscall-x86-64")
set_property(CACHE native-call-forwarder PROPERTY STRINGS ${possible-native-forwarders})

if(${native-call-forwarder} STREQUAL syscall-x86-64)
    list(APPEND SRC_FILES hooks/native-syscalls-x86-64.c)
    message(STATUS "Native call policy: directly invoking syscall (native-call-forwarder=syscall-x86-64).")
elseif(${native-call-forwarder} STREQUAL libc)
    list(APPEND SRC_FILES hooks/native-libc.c)
    message(STATUS "Native call policy: forward request to native libc (native-call-forwarder=libc).")
else()
    message(FATAL_ERROR "Invalid native-call-forwarder, must be one of ${possible-native-forwarders}")
endif()

add_library(netfuzzlib SHARED ${SRC_FILES})

add_library(netfuzzlib-asan SHARED ${SRC_FILES})
target_compile_options(netfuzzlib-asan PUBLIC -fsanitize=address)
target_link_options(netfuzzlib-asan PUBLIC -fsanitize=address)

add_library(netfuzzlib-static STATIC ${SRC_FILES})
target_compile_definitions(netfuzzlib-static PUBLIC MODULE_STATIC_LINKED STATIC_LIBRARY)

add_library(netfuzzlib-static-asan STATIC ${SRC_FILES})
target_compile_definitions(netfuzzlib-static-asan PUBLIC MODULE_STATIC_LINKED STATIC_LIBRARY)
target_compile_options(netfuzzlib-static-asan PUBLIC -fsanitize=address)
target_link_options(netfuzzlib-static-asan PUBLIC -fsanitize=address)

set(KLEE_CFLAGS
        -D_FORTIFY_SOURCE=0
        -D_GNU_SOURCE
        -DDEBUG=1
        -DMODULE_STATIC_LINKED
        -Wall
        -Wwrite-strings
        -Xclang
        -disable-O0-optnone
        -DINITIALIZE_NETWORK_MODEL_MANUAL
        -g
        -I${CMAKE_SOURCE_DIR}/src
        -I${CMAKE_SOURCE_DIR}/modules/include)
prefix_with_path("${SRC_FILES}" "${CMAKE_CURRENT_SOURCE_DIR}/" SRC_FILES_ABSOLUTE_PATH)
add_bitcode_library_targets(netfuzzlib-klee "${SRC_FILES_ABSOLUTE_PATH}" "${KLEE_CFLAGS}")
add_bitcode_library_targets(netfuzzlib-klee-debug "${SRC_FILES_ABSOLUTE_PATH}" "${KLEE_CFLAGS}" "-DDEBUG")