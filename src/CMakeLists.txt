nfl_add_dual_library(netfuzzlib SOURCES
        init.c
        callback_wrapper.c
        core/fd_table.c
        core/getifaddrs.c
        core/import_host.c
        core/interfaces.c
        core/ioctl.c
        core/network_env.c
        core/resolver.c
        core/routing.c
        core/addr.c
        interceptors/interceptors.c
        interceptors/io_uring.c
        interceptors/poll.c
        interceptors/stdio.c
        core/log.c
        interceptors/native.c
        core/dup.c
        core/epoll.c
        core/poll.c
        core/core.c
        core/dgram.c
        core/rtnetlink.c
        core/stream.c
        core/recv_buffer.c
        core/sockopt.c
        core/stdio.c
        core/libnl.c)

set_source_files_properties(interceptors/interceptors.c PROPERTIES
        COMPILE_FLAGS "-Wno-incompatible-pointer-types")

target_link_libraries(netfuzzlib PRIVATE ${CMAKE_DL_LIBS})

# The resulting artifacts are libnfl.so / libnfl.a. The CMake target keeps the
# name `netfuzzlib` (so internal target references need no churn); only the
# output filename is `nfl`.
set_target_properties(netfuzzlib netfuzzlib_static PROPERTIES OUTPUT_NAME nfl)

# Force the linker to pull init.o from the static archive so the constructor
# in nfl_initialize fires.
target_link_options(netfuzzlib_static INTERFACE "LINKER:-u,nfl_initialize")