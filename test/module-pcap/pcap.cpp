#include <gtest/gtest.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

extern "C" {
#include "../../src/environment/network_env.h"
#include "../../modules/module-pcap/pcap-loader.h"
}

class TestPCAP : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_pcap_file("config/single_udp_packet.pcap");
    }
};

static void check_ip_pktinfo(struct msghdr *my_msghdr, int ifindex, const char *ipi_addr, const char *ipi_spec_dst) {
    cmsghdr *cmsg;
    bool ip_pktinfo_seen = false;
    for (cmsg = CMSG_FIRSTHDR(my_msghdr); cmsg; cmsg = CMSG_NXTHDR(my_msghdr, cmsg)) {
        if (cmsg->cmsg_level == IPPROTO_IP && cmsg->cmsg_type == IP_PKTINFO) {
            struct in_pktinfo *pktinfo = ((struct in_pktinfo *)CMSG_DATA(cmsg));
            ASSERT_EQ(pktinfo->ipi_ifindex, ifindex);
            ASSERT_STREQ(inet_ntoa(pktinfo->ipi_addr), ipi_addr);
            ASSERT_STREQ(inet_ntoa(pktinfo->ipi_spec_dst), ipi_spec_dst);
            ip_pktinfo_seen = true;
        }
    }
    ASSERT_TRUE(ip_pktinfo_seen);
}

TEST_F(TestPCAP, test_recvmsg_udp_single_packet) {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GT(socket_fd, 0);
    struct sockaddr_in bound_addr = {};

    bound_addr.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &bound_addr.sin_addr);
    bound_addr.sin_port = htons(5353);

    int ret = bind(socket_fd, (struct sockaddr *)&bound_addr, sizeof(bound_addr));
    ASSERT_EQ(ret, 0);
    const int on = 1;
    ret = setsockopt(socket_fd, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    ASSERT_EQ(ret, 0);
    int val = -1;
    socklen_t val_len = sizeof(int);
    ret = getsockopt(socket_fd, IPPROTO_IP, IP_PKTINFO, (void *)&val, &val_len);
    ASSERT_EQ(ret, 0);
    ASSERT_NE(val, 0);

    struct msghdr my_msghdr = {};
    struct iovec iov = {};
    struct sockaddr_in msg_name_buffer = {};
    iov.iov_base = calloc(1, 2000);
    iov.iov_len = 2000;

    my_msghdr.msg_name = &msg_name_buffer;
    my_msghdr.msg_namelen = sizeof(struct sockaddr_in);
    my_msghdr.msg_control = calloc(1, 1000);
    my_msghdr.msg_controllen = 1000;
    my_msghdr.msg_iov = &iov;
    my_msghdr.msg_iovlen = 1;

    ssize_t bytes_received = recvmsg(socket_fd, &my_msghdr, 0);
    ASSERT_EQ(bytes_received, 28);
    char message[] = "\x10\x32\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c\x65\x03\x63\x6f\x6d\x00\x00\x10\x00\x01";
    for (int i = 0; i < sizeof(message); i++) {
        ASSERT_EQ(((char *)iov.iov_base)[i], message[i]);
    }
    ASSERT_STREQ(inet_ntoa(msg_name_buffer.sin_addr), "127.0.0.1");
    check_ip_pktinfo(&my_msghdr, 1, "127.0.0.1", "127.0.0.1");
}

TEST_F(TestPCAP, test_recv_udp_all_packets) {
    //    int socket_fd1 = socket(AF_INET, SOCK_DGRAM, 0);
    //    int socket_fd2 = socket(AF_INET, SOCK_DGRAM, 0);
    //
    //    ASSERT_GT(socket_fd1, 0);
    //    ASSERT_GT(socket_fd2, 0);
    //
    //    struct sockaddr_in bound_addr1 = {};
    //    struct sockaddr_in bound_addr2 = {};
    //
    //    bound_addr1.sin_family = AF_INET;
    //    inet_pton(AF_INET, "127.0.0.1", &bound_addr1.sin_addr);
    //    bound_addr1.sin_port = htons(5353);
    //
    //    bound_addr2.sin_family = AF_INET;
    //    inet_pton(AF_INET, "0.0.0.0", &bound_addr2.sin_addr);
    //    bound_addr2.sin_port = htons(49183);
    //    int on = 1;
    //    int ret = setsockopt(socket_fd2, IPPROTO_IP, IP_PKTINFO, &on, sizeof(on));
    //    ASSERT_EQ(ret, 0);
    //
    //    ret = bind(socket_fd1, (struct sockaddr *) &bound_addr1, sizeof(bound_addr1));
    //    ASSERT_EQ(ret, 0);
    //    ret = bind(socket_fd2, (struct sockaddr *) &bound_addr2, sizeof(bound_addr2));
    //    ASSERT_EQ(ret, 0);
    //
    //    struct msghdr my_msghdr = {};
    //    struct iovec iov = {};
    //    struct sockaddr_in msg_name_buffer = {};
    //    iov.iov_base = calloc(1, 2000);
    //    iov.iov_len = 2000;
    //
    //    my_msghdr.msg_name = &msg_name_buffer;
    //    my_msghdr.msg_namelen = sizeof(struct sockaddr_in);
    //    my_msghdr.msg_control = calloc(1, 1000);
    //    my_msghdr.msg_controllen = 1000;
    //    my_msghdr.msg_iov = &iov;
    //    my_msghdr.msg_iovlen = 1;
    //
    //    ssize_t bytes_received = recvmsg(socket_fd1, &my_msghdr, 0);
    //    ASSERT_EQ(bytes_received, 28);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 28);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, 10, 0);
    //    ASSERT_EQ(bytes_received, 10);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 43);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 32);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 32);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 29);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 25);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, 0);
    //    ASSERT_EQ(bytes_received, 56);
    //    bytes_received = recv(socket_fd1, &iov.iov_base, iov.iov_len, MSG_DONTWAIT);
    //    ASSERT_EQ(bytes_received, 0);
    //    ASSERT_EQ(errno, EAGAIN);
    //    ASSERT_EXIT(recvfrom(socket_fd1, &iov.iov_base, iov.iov_len, 0, nullptr, nullptr), testing::ExitedWithCode(1), "");
}