set(SRC_FILES
        gtest.cpp

        udp-ipv4-accept.cpp
        udp-ipv4-bind.cpp
        udp-ipv4-connect.cpp
        udp-ipv4-others.cpp
        udp-ipv4-pair.cpp
        udp-ipv4-send.cpp
        udp-ipv4-shutdown.cpp
        udp-ipv4-trio.cpp)

set(KERNEL_TEST_RENAME
        TestUDPv4Accept=TestUDPIpv4AcceptKernel
        TestUDPv4Bind=TestUDPIpv4BindKernel
        TestUDPv4Connect=TestUDPIpv4ConnectKernel
        TestUDPv4Others=TestUDPIpv4OthersKernel
        TestUDPv4Pair=TestUDPIpv4PairKernel
        TestUDPv4Send=TestUDPIpv4SendKernel
        TestUDPv4Shutdown=TestUDPIpv4ShutdownKernel
        TestUDPv4Trio=TestUDPIpv4TrioKernel)


add_executable(runUnitTestsUdpIpv4 ${SRC_FILES})
target_link_libraries(runUnitTestsUdpIpv4 gtest gmock netfuzzlib module-config-file-unittest)
gtest_add_tests(runUnitTestsUdpIpv4 "" AUTO)

#add_executable(runUnitTestsUdpIpv4Kernel ${SRC_FILES})
#target_link_libraries(runUnitTestsUdpIpv4Kernel gtest gmock)
#target_compile_definitions(runUnitTestsUdpIpv4Kernel PRIVATE TEST_KERNEL)
#target_compile_definitions(runUnitTestsUdpIpv4Kernel PRIVATE ${KERNEL_TEST_RENAME})
#gtest_add_tests(runUnitTestsUdpIpv4Kernel "" AUTO)
