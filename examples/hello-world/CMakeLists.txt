nfl_add_dual_library(nfl-hello-world SOURCES hello-world.c)

target_link_libraries(nfl-hello-world PRIVATE
        -Wl,--whole-archive netfuzzlib_static -Wl,--no-whole-archive
        ${CMAKE_DL_LIBS})
