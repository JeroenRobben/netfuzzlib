#include <gtest/gtest.h>

extern "C" {
#include <netinet/in.h>

#include <sys/socket.h>
#include <sys/types.h>
#include "../../src/environment/network_env.h"
#include "module.h"
}

class TestTCPPoll : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/tcp2.conf");
    }
};
;

TEST_F(TestTCPPoll, test_pollNoConns) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd, -1);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    ASSERT_EQ(ret, 0);

    listen(fd, 100);
    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;

    ret = poll(fds, 1, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(fds[0].revents & POLLIN);

    ret = close(fd);
    ASSERT_EQ(ret, 0);
}

TEST_F(TestTCPPoll, test_poll) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_NE(fd, -1);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(2000);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int ret = bind(fd, (struct sockaddr *)&addr, sizeof(addr));
    ASSERT_EQ(ret, 0);

    struct pollfd fds[1];
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    ret = poll(fds, 1, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(fds[0].revents & POLLIN);

    listen(fd, 100);
    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;

    ret = poll(fds, 1, 0);
    ASSERT_EQ(ret, 1);
    ASSERT_TRUE(fds[0].revents & POLLIN);

    accept(fd, NULL, NULL);

    fds[0].fd = fd;
    fds[0].events = POLLIN;
    fds[0].revents = 0;
    ret = poll(fds, 1, 0);
    ASSERT_EQ(ret, 1);
    ASSERT_TRUE(fds[0].revents & POLLIN);

    accept(fd, NULL, NULL);

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    ret = poll(fds, 1, 0);
    ASSERT_EQ(ret, 0);
    ASSERT_FALSE(fds[0].revents & POLLIN);

    ret = close(fd);
    ASSERT_EQ(ret, 0);
}