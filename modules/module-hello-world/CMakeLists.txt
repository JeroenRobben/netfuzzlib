cmake_minimum_required(VERSION 3.15)
project(module-hello-world C)
set(CMAKE_C_STANDARD 11)

add_compile_definitions(_GNU_SOURCE)

add_library(module-hello-world SHARED module.c)
target_compile_options(module-hello-world PUBLIC -g)
target_link_options(module-hello-world PUBLIC -g)
target_include_directories(module-hello-world PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

add_library(module-hello-world-static STATIC module.c)
target_include_directories(module-hello-world-static PUBLIC ${CMAKE_SOURCE_DIR}/modules/include include)

check_include_file("klee/klee.h" HAVE_KLEE)
if(HAVE_KLEE)
    set(LIB_CFLAGS
            -D_FORTIFY_SOURCE=0
            -D_GNU_SOURCE
            -Wall
            -Wwrite-strings
            -Xclang
            -disable-O0-optnone
            -I${CMAKE_SOURCE_DIR}/modules/include
            -I${CMAKE_CURRENT_SOURCE_DIR}/include
            -DKLEE_ENABLED
            -g)
    add_bitcode_library_targets(module-hello-world-klee "${CMAKE_CURRENT_SOURCE_DIR}/module.c" "${LIB_CFLAGS}")
else()
    message(WARNING "Could not find klee/klee.h, disabling target module-hello-world-klee")
endif()
