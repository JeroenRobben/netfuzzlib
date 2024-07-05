#===------------------------------------------------------------------------===#
#
#                     The KLEE Symbolic Virtual Machine
#
# This file is distributed under the University of Illinois Open Source
# License. See LICENSE.TXT for details.
#
#===------------------------------------------------------------------------===#
#
# This file tries to find compilers to build LLVM bitcode.
# It is implicitly dependent on `find_llvm.cmake` already being run in the
# same scope.
#
#===------------------------------------------------------------------------===#

message(STATUS "Looking for bitcode compilers")

find_program(
        LLVMCC
        NAMES "clang-${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}" "clang" "llvm-gcc"
        # Give the LLVM tools directory higher priority than the system directory.
        HINTS "${LLVM_TOOLS_BINARY_DIR}"
)
if (LLVMCC)
    message(STATUS "Found ${LLVMCC}")
else()
    message(FATAL_ERROR "Failed to find C bitcode compiler")
endif()

find_program(
        LLVMCXX
        NAMES "clang++-${LLVM_VERSION_MAJOR}.${LLVM_VERSION_MINOR}" "clang++" "llvm-g++"
        # Give the LLVM tools directory higher priority than the system directory.
        HINTS "${LLVM_TOOLS_BINARY_DIR}"
)
if (LLVMCXX)
    message(STATUS "Found ${LLVMCXX}")
else()
    message(FATAL_ERROR "Failed to find C++ bitcode compiler")
endif()

# Test compiler
function(test_bitcode_compiler COMPILER SRC_EXT)
    message(STATUS "Testing bitcode compiler ${COMPILER}")
    set(SRC_FILE "${CMAKE_BINARY_DIR}/test_bitcode_compiler.${SRC_EXT}")
    file(WRITE "${SRC_FILE}" "int main(int argc, char** argv) { return 0;}")
    set(BC_FILE "${SRC_FILE}.bc")
    execute_process(
            COMMAND
            "${COMPILER}"
            "-c"
            "-emit-llvm"
            "-o" "${BC_FILE}"
            "${SRC_FILE}"
            RESULT_VARIABLE COMPILE_INVOKE_EXIT_CODE
    )
    if ("${COMPILE_INVOKE_EXIT_CODE}" EQUAL 0)
        message(STATUS "Compile success")
    else()
        message(FATAL_ERROR "Compilation failed")
    endif()

    # Remove temporary files. It's okay to not remove these on failure
    # as they will be useful for developer debugging.
    file(REMOVE "${SRC_FILE}")
    file(REMOVE "${BC_FILE}")
endfunction()

test_bitcode_compiler("${LLVMCC}" "c")
test_bitcode_compiler("${LLVMCXX}" "cxx")
