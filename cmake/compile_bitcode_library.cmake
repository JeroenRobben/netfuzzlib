function(prefix_with_path files prefix output_var)
    set(_result)
    foreach(file ${files})
        list(APPEND _result "${prefix}${file}")
    endforeach()
    set(${output_var} "${_result}" PARENT_SCOPE)
endfunction(prefix_with_path)


function(add_bitcode_library_targets library_name source_files cflags)
    # Compile every source file
    set(BC_FILES)
    foreach(source_file ${source_files})
        # Get filename without extension
        get_filename_component(file_name_only "${source_file}" NAME_WE)
        set(bc_file "${CMAKE_CURRENT_BINARY_DIR}/${file_name_only}${opt_suffix}.bc" )
        get_filename_component(source_file_type "${source_file}" EXT)
        if("${source_file_type}" STREQUAL ".cpp")
            add_custom_command(
                    OUTPUT ${bc_file}
                    COMMAND ${LLVMCXX} -c "-emit-llvm" ${cflags} "${source_file}" -o ${bc_file}
                    DEPENDS ${source_file}
            )
        else()
            add_custom_command(
                    OUTPUT ${bc_file}
                    COMMAND ${LLVMCC} -c "-emit-llvm" ${cflags} "${source_file}" -o ${bc_file}
                    DEPENDS ${source_file}
            )
        endif()

        list(APPEND BC_FILES ${bc_file})
    endforeach()

    # Add command to link them to an archive
    add_custom_command(
            OUTPUT ${CMAKE_BINARY_DIR}/lib${library_name}.bca
            COMMAND llvm-ar rcs ${CMAKE_BINARY_DIR}/lib${library_name}.bca ${BC_FILES}
            DEPENDS ${BC_FILES}
    )

    add_custom_target(${library_name} DEPENDS "${CMAKE_BINARY_DIR}/lib${library_name}.bca")
endfunction(add_bitcode_library_targets)