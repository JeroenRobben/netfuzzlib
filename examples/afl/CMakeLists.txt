nfl_add_dual_library(nfl-afl SOURCES
        afl.c
        config.c
        child_tracker.c
        afl_init.c)

target_link_libraries(nfl-afl PRIVATE
        -Wl,--whole-archive netfuzzlib_static -Wl,--no-whole-archive
        ${CMAKE_DL_LIBS})
