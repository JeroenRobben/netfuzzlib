cmake_minimum_required(VERSION 3.15)
project(module-pcap C)
set(CMAKE_C_STANDARD 11)

add_compile_definitions(_GNU_SOURCE)

set(SRC_FILES
        module-afl.c
        module-afl-config.c
        )

add_library(module-afl SHARED ${SRC_FILES})
target_include_directories(module-afl PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

add_library(module-afl-static STATIC ${SRC_FILES})
target_include_directories(module-afl-static PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

add_library(module-afl-static-debug STATIC ${SRC_FILES})
target_compile_definitions(module-afl-static-debug PUBLIC DEBUG)
target_include_directories(module-afl-static-debug PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

add_library(module-afl-debug SHARED ${SRC_FILES})
target_compile_definitions(module-afl-debug PUBLIC DEBUG)
target_include_directories(module-afl-debug PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

