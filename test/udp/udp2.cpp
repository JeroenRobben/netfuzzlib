#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <string.h>

#include <gtest/gtest.h>

extern "C" {
#include <netfuzzlib/module_api.h>
#include "module.h"
#include "environment/network_env.h"
}

class TestUDP2 : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/udp2.conf");
    }
};

TEST_F(TestUDP2, udp4) {
    int fd;
    struct sockaddr_in6 local_addr, remote_addr;
    fd = socket(AF_INET6, SOCK_DGRAM, 0);
    ASSERT_TRUE(fd > 0);
    memset(&local_addr, 0, sizeof(struct sockaddr_in6));
    memset(&remote_addr, 0, sizeof(struct sockaddr_in6));

    local_addr.sin6_family = AF_INET6;
    local_addr.sin6_port = htons(5000);

    inet_pton(AF_INET6, "::1", &local_addr.sin6_addr);
    int res = bind(fd, reinterpret_cast<const sockaddr *>(&local_addr), sizeof(struct sockaddr_in6));
    ASSERT_EQ(res, 0);

    ssize_t n;
    socklen_t len = sizeof(struct sockaddr_in6);
    char buffer[2200];
    n = recvfrom(fd, buffer, 2200, MSG_WAITALL, (struct sockaddr *)&remote_addr, &len);

    ASSERT_EQ(n, 2050);
    uint8_t val_1 = buffer[0];
    uint8_t val_1_expected = '\x85';
    ASSERT_EQ(val_1, val_1_expected);

    ASSERT_TRUE(buffer[sizeof(val_1)] != 0 || buffer[sizeof(val_1) + 1] != 0);
    close(fd);
}