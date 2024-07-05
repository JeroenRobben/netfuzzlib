if(${CMAKE_VERSION} VERSION_GREATER "3.24")
    cmake_policy(SET CMP0135 NEW)
endif()

include(FetchContent)
FetchContent_Declare(googletest URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

add_subdirectory(config)
add_subdirectory(udp/ipv4)

add_executable(runUnitTests
        gtest.cpp

        environment/ioctl/ioctl1.cpp
        environment/others/others.cpp
        environment/others/dup.cpp
        environment/others/stdio.cpp
        environment/routing/routing.cpp

        environment/rtnetlink/getaddr/rtnetlink_getaddr_filter.cpp
        environment/rtnetlink/getaddr/rtnetlink_getaddr_no_filter.cpp
        environment/rtnetlink/getaddr/rtnetlink_getaddr_single_interface.cpp

        environment/rtnetlink/getlink/rtnetlink_getlink_all_devices.cpp
        environment/rtnetlink/getlink/rtnetlink_getlink_single_device_filter.cpp
        environment/rtnetlink/getlink/rtnetlink_getlink_single_device_no_filter.cpp
        environment/rtnetlink/getlink/rtnetlink_getlink_test_helper.cpp

        icmp/ipv6/icmpv6.cpp

        tcp/tcp1.cpp
        tcp/tcp-poll.cpp

        udp/udp1.cpp
        udp/udp2.cpp
        udp/udp_connect.cpp)

target_link_libraries(runUnitTests gtest gmock
        module-config-file-unittest
        netfuzzlib)

add_executable(runUnitTestsPcap
        gtest.cpp
        module-pcap/pcap.cpp)

target_link_libraries(runUnitTestsPcap gtest gmock
        module-pcap-unittest
        netfuzzlib)

gtest_add_tests(runUnitTests "" AUTO)
gtest_add_tests(runUnitTestsPcap "" AUTO)
gtest_discover_tests(runUnitTests runUnitTestsPcap)