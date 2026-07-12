cmake_minimum_required(VERSION 3.28)
project(netfuzzlib C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

option(NFL_ASAN "Build with AddressSanitizer" OFF)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake)
include(nfl_helpers)

add_library(netfuzzlib_headers INTERFACE)
target_include_directories(netfuzzlib_headers INTERFACE include src)
target_compile_definitions(netfuzzlib_headers INTERFACE
        _GNU_SOURCE
        $<$<CONFIG:Debug>:NFL_DEBUG>)

if(NFL_ASAN)
    target_compile_options(netfuzzlib_headers INTERFACE -fsanitize=address)
    target_link_options(netfuzzlib_headers INTERFACE -fsanitize=address)
    # Clang defaults to the static ASan runtime for executables and the dynamic
    # one for shared libs — mixing the two (e.g. LD_PRELOADing an ASan shared
    # lib into a statically-instrumented program) trips "incompatible ASan
    # runtimes" at startup. Force the dynamic runtime everywhere. gcc already
    # uses the shared libasan by default, so this flag is clang-only.
    if(CMAKE_C_COMPILER_ID MATCHES "Clang")
        target_compile_options(netfuzzlib_headers INTERFACE -shared-libasan)
        target_link_options(netfuzzlib_headers INTERFACE -shared-libasan)
        # libclang_rt.asan-<arch>.so lives under clang's resource dir, which is
        # not on the dynamic linker's default search path. Bake an rpath into
        # every consumer so the runtime resolves at load time without LD_LIBRARY_PATH.
        execute_process(
            COMMAND ${CMAKE_C_COMPILER} -print-file-name=libclang_rt.asan-${CMAKE_SYSTEM_PROCESSOR}.so
            OUTPUT_VARIABLE NFL_CLANG_ASAN_RUNTIME
            OUTPUT_STRIP_TRAILING_WHITESPACE)
        if(NFL_CLANG_ASAN_RUNTIME AND EXISTS "${NFL_CLANG_ASAN_RUNTIME}")
            get_filename_component(NFL_CLANG_ASAN_RUNTIME_DIR "${NFL_CLANG_ASAN_RUNTIME}" DIRECTORY)
            target_link_options(netfuzzlib_headers INTERFACE
                    "LINKER:-rpath,${NFL_CLANG_ASAN_RUNTIME_DIR}")
        endif()
    endif()
endif()

add_subdirectory(src)
add_subdirectory(examples/hello-world)
add_subdirectory(examples/afl)
# module-bridge-kernel is test-only — see test/modules/CMakeLists.txt.

option(NFL_BUILD_TESTS "Build netfuzzlib's test suite (gtest + integration)" ON)
if(NFL_BUILD_TESTS)
    enable_testing()
    add_subdirectory(test)
endif()
