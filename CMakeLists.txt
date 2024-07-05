cmake_minimum_required(VERSION 3.15)
project(netfuzzlib C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 11)

add_compile_definitions(_GNU_SOURCE)
add_compile_options(-g)
add_link_options(-g -ldl)

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_definitions(NFL_DEBUG)
endif ()

include_directories(include)
include_directories(src)

include(cmake/find_bitcode_compiler.cmake)
include(cmake/compile_bitcode_library.cmake)


add_subdirectory(test)
add_subdirectory(src)
add_subdirectory(modules/module-config-file)
add_subdirectory(modules/module-hello-world)
add_subdirectory(modules/module-pcap)
add_subdirectory(modules/module-afl)
add_subdirectory(modules/module-aflnet)
add_subdirectory(modules/module-aflnet-replay)



