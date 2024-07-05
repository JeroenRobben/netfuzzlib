#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include <gtest/gtest.h>

extern "C" {
#include <netfuzzlib/module_api.h>
#include "module.h"
#include "environment/network_env.h"
}

class TestUDPConnect : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/udp.conf");
    }
};

//Check connect behaviour on udp socket
TEST_F(TestUDPConnect, udp_connect) {
    int sockfd;
    char message_text[] = "Hello from server\n";
    size_t message_text_len = strlen(message_text);
    struct sockaddr_in remote_addr_1, remote_addr_2;

    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    memset(&remote_addr_1, 0, sizeof(remote_addr_1));
    memset(&remote_addr_2, 0, sizeof(remote_addr_2));

    remote_addr_1.sin_family = AF_INET; // IPv4
    inet_pton(AF_INET, "127.0.0.2", &remote_addr_1.sin_addr.s_addr);
    remote_addr_1.sin_port = htons(8000);

    remote_addr_2.sin_family = AF_INET; // IPv4
    inet_pton(AF_INET, "127.0.0.3", &remote_addr_2.sin_addr.s_addr);
    remote_addr_2.sin_port = htons(8002);

    struct iovec iov[1];
    iov[0].iov_base = message_text;
    iov[0].iov_len = message_text_len;

    struct msghdr message;
    message.msg_name = &remote_addr_1;
    message.msg_namelen = sizeof(remote_addr_1);
    message.msg_iov = iov;
    message.msg_iovlen = 1;
    message.msg_control = 0;
    message.msg_controllen = 0;

    char receive_buffer[100];
    size_t receive_buffer_size = sizeof(receive_buffer);

    int len = sizeof(remote_addr_1);
    ssize_t ret;

    //sending on udp socket without default remote address should fail.
    ret = send(sockfd, (const char *)message_text, message_text_len, 0);
    ASSERT_EQ(ret, -1);

    ret = write(sockfd, (const char *)message_text, message_text_len);
    ASSERT_EQ(ret, -1);

    //Using sendto should not touch default remote address.
    ret = sendto(sockfd, (const char *)message_text, message_text_len, MSG_CONFIRM, (const struct sockaddr *)&remote_addr_1, len);
    ASSERT_EQ(ret, message_text_len);

    ret = send(sockfd, (const char *)message_text, message_text_len, 0);
    ASSERT_EQ(ret, -1);

    ret = write(sockfd, (const char *)message_text, message_text_len);
    ASSERT_EQ(ret, -1);

    //Using sendmsg should not touch default remote address.
    ret = sendmsg(sockfd, &message, 0);
    ASSERT_EQ(ret, message_text_len);

    ret = send(sockfd, (const char *)message_text, message_text_len, 0);
    ASSERT_EQ(ret, -1);

    ret = write(sockfd, (const char *)message_text, message_text_len);
    ASSERT_EQ(ret, -1);

    //Using connect should set the default remote address.
    ret = connect(sockfd, (const struct sockaddr *)&remote_addr_1, len);
    ASSERT_EQ(ret, 0);

    ret = send(sockfd, (const char *)message_text, message_text_len, 0);
    ASSERT_EQ(ret, message_text_len);

    ret = write(sockfd, (const char *)message_text, message_text_len);
    ASSERT_EQ(ret, message_text_len);

    //Sending to another address as the default address
    ret = sendto(sockfd, (const char *)message_text, message_text_len, MSG_CONFIRM, (const struct sockaddr *)&remote_addr_2, len);
    ASSERT_EQ(ret, message_text_len);

    //Calling connect with NULL parameters should remove the default address
    ret = connect(sockfd, NULL, 0);
    ASSERT_EQ(ret, 0);

    //Sending should fail, since there is no default address
    ret = send(sockfd, (const char *)message_text, message_text_len, 0);
    ASSERT_EQ(ret, -1);

    ret = write(sockfd, (const char *)message_text, message_text_len);
    ASSERT_EQ(ret, -1);

    ret = sendto(sockfd, (const char *)message_text, message_text_len, MSG_CONFIRM, (const struct sockaddr *)&remote_addr_2, len);
    ASSERT_EQ(ret, message_text_len);
}
