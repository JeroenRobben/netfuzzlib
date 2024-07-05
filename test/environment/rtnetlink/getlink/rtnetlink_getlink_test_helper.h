#ifndef NETFUZZLIB_RTNETLINK_GETLINK_TEST_HELPER_CPP_H
#define NETFUZZLIB_RTNETLINK_GETLINK_TEST_HELPER_CPP_H

void test_link(const struct nlmsghdr *msg, const char *name, const char *hw_addr, const char *hw_broadcast_addr, int mtu, unsigned int flags);

#endif //NETFUZZLIB_RTNETLINK_GETLINK_TEST_HELPER_CPP_H
