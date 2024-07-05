#include <gtest/gtest.h>
#include <arpa/inet.h>

extern "C" {
#include "../../../include/netfuzzlib/module_api.h"
#include "module.h"
#include "../../../src/environment/network_env.h"
}

class TestEnvironmentStdio : public ::testing::Test {
protected:
    int sockfd1;
    int sockfd2;

    void SetUp() override {
        init_main_library();
        load_config_file("config/tcp2.conf");

        struct sockaddr_in remote_addr {};

        sockfd1 = socket(AF_INET, SOCK_STREAM, 0);
        remote_addr.sin_family = AF_INET;
        inet_aton("127.0.0.5", &remote_addr.sin_addr);
        remote_addr.sin_port = htons(5000);
        connect(sockfd1, reinterpret_cast<const sockaddr *>(&remote_addr), sizeof(remote_addr));

        sockfd2 = socket(AF_INET, SOCK_STREAM, 0);
        remote_addr.sin_family = AF_INET;
        inet_aton("127.0.0.5", &remote_addr.sin_addr);
        remote_addr.sin_port = htons(8000);
        connect(sockfd2, reinterpret_cast<const sockaddr *>(&remote_addr), sizeof(remote_addr));
    }
};

TEST_F(TestEnvironmentStdio, testFgetCEOF) {
    FILE *sockfd1_stream = fdopen(sockfd1, "w");
    ASSERT_TRUE(sockfd1_stream != nullptr);
    ASSERT_EQ(fileno(sockfd1_stream), sockfd1);

    int c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, 0x06);
    c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, 0x10);
    c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, 0xaa);
    c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, EOF);
}

TEST_F(TestEnvironmentStdio, testFgetCClose) {
    FILE *sockfd1_stream = fdopen(sockfd1, "w");
    ASSERT_TRUE(sockfd1_stream != nullptr);
    ASSERT_EQ((long)sockfd1_stream, sockfd1);
    ASSERT_EQ(fileno(sockfd1_stream), sockfd1);

    int c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, 0x06);

    c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, 0x10);

    ASSERT_EQ(0, fclose(sockfd1_stream));
    FILE *sockfd1_stream_copy = fdopen(sockfd1, "w");
    ASSERT_EQ(nullptr, sockfd1_stream_copy);

    c = fgetc(sockfd1_stream);
    ASSERT_EQ(c, EOF);
}

TEST_F(TestEnvironmentStdio, testFgetsNewline) {
    char buf[10]{};

    FILE *sockfd2_stream = fdopen(sockfd2, "w");
    ASSERT_TRUE(sockfd2_stream != nullptr);
    ASSERT_EQ(fileno(sockfd2_stream), sockfd2);

    buf[1] = 10;
    ASSERT_EQ(fgets(buf, 2, sockfd2_stream), buf);
    ASSERT_EQ(buf[0], 0x01);
    ASSERT_EQ(buf[1], '\0');

    buf[3] = 10;
    ASSERT_EQ(fgets(buf, 10, sockfd2_stream), buf);
    ASSERT_EQ(buf[0], 0x02);
    ASSERT_EQ(buf[1], 0x04);
    ASSERT_EQ(buf[2], '\n');
    ASSERT_EQ(buf[3], '\0');

    ASSERT_EQ(fgets(buf, 10, sockfd2_stream), nullptr);
}

TEST_F(TestEnvironmentStdio, testFgets2) {
    char buf[10]{};

    FILE *sockfd1_stream = fdopen(sockfd1, "w");
    ASSERT_TRUE(sockfd1_stream != nullptr);
    ASSERT_EQ(fileno(sockfd1_stream), sockfd1);

    ASSERT_EQ(fgets(buf, 10, sockfd1_stream), nullptr);
}
