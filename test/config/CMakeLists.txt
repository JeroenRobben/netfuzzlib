set(CONF_FILES
        empty.conf
        icmp.conf
        ioctl1.conf
        network.conf
        routing-gateway.conf
        routing-no-gateway.conf
        rtnetlink-multiple-interfaces.conf
        tcp1.conf
        tcp2.conf
        udp.conf
        udp2.conf
        single_udp_packet.pcap)

foreach(CONF_FILE ${CONF_FILES})
    configure_file(${CONF_FILE} ${CMAKE_CURRENT_BINARY_DIR}/${CONF_FILE} COPYONLY)
endforeach()
