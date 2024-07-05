#include <gtest/gtest.h>
#include <arpa/inet.h>

extern "C" {
#include "../../../include/netfuzzlib/module_api.h"
#include "module.h"
#include "../../../src/environment/network_env.h"
}

class TestEnvironmentDup : public ::testing::Test {
protected:
    int sockfd;

    void SetUp() override {
        init_main_library();
        load_config_file("config/tcp1.conf");

        struct sockaddr_in remote_addr {};

        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        remote_addr.sin_family = AF_INET;
        inet_aton("127.0.0.5", &remote_addr.sin_addr);
        remote_addr.sin_port = htons(5000);
        connect(sockfd, reinterpret_cast<const sockaddr *>(&remote_addr), sizeof(remote_addr));
    }
};

TEST_F(TestEnvironmentDup, testDup) {
    char buf[10]{};

    ssize_t ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x06);
    int dupfd = dup(sockfd);
    ASSERT_GT(dupfd, 0);

    ret = read(dupfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x10);

    ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], '\xAA');
}

TEST_F(TestEnvironmentDup, testDup2) {
    char buf[10]{};
    int dupfd = 200;

    ssize_t ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x06);
    int result = dup2(sockfd, dupfd);
    ASSERT_EQ(result, dupfd);

    ret = read(dupfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x10);

    ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], '\xAA');
}

TEST_F(TestEnvironmentDup, testDup3) {
    char buf[10]{};
    int dupfd = 200;

    ssize_t ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x06);
    int result = dup3(sockfd, dupfd, 0);
    ASSERT_EQ(result, dupfd);

    ret = read(dupfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], 0x10);

    ret = read(sockfd, buf, 1);
    ASSERT_EQ(ret, 1);
    ASSERT_EQ(buf[0], '\xAA');
}
