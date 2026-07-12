function(nfl_add_dual_library NAME)
    cmake_parse_arguments(NFL "" "" "SOURCES" ${ARGN})

    add_library(${NAME}_objects OBJECT ${NFL_SOURCES})
    set_target_properties(${NAME}_objects PROPERTIES POSITION_INDEPENDENT_CODE ON)
    target_link_libraries(${NAME}_objects PRIVATE netfuzzlib_headers)

    add_library(${NAME} SHARED $<TARGET_OBJECTS:${NAME}_objects>)
    target_link_libraries(${NAME} PRIVATE netfuzzlib_headers)

    add_library(${NAME}_static STATIC $<TARGET_OBJECTS:${NAME}_objects>)
    set_target_properties(${NAME}_static PROPERTIES OUTPUT_NAME ${NAME})
    target_link_libraries(${NAME}_static PRIVATE netfuzzlib_headers)
endfunction()
