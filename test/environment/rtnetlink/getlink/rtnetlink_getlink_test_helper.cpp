#include <gtest/gtest.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <net/ethernet.h>
#include "rtnetlink_getlink_test_helper.h"

void test_link(const struct nlmsghdr *msg, const char *name, const char *hw_addr, const char *hw_broadcast_addr, int mtu, unsigned int flags) {
    struct ifinfomsg *ifinfo;
    struct rtattr *attr;
    unsigned long len;

    ifinfo = (struct ifinfomsg *)NLMSG_DATA(msg);
    ASSERT_EQ(ifinfo->ifi_flags, flags);
    len = msg->nlmsg_len - NLMSG_ALIGN(sizeof(struct ifinfomsg) + NLMSG_ALIGN(sizeof(struct nlmsghdr)));
    int attr_count = 0;

    bool ifla_address_seen = false, ifla_broadcast_seen = false, ifla_name_seen = false, ifla_mtu_seen = false, ifla_qdisc_seen = false,
         ifla_stats_seen = false;

    for (attr = IFLA_RTA(ifinfo); RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
        attr_count++;
        switch (attr->rta_type) {
        case IFLA_ADDRESS:
            ifla_address_seen = true;
            ASSERT_EQ(memcmp(hw_addr, RTA_DATA(attr), ETHER_ADDR_LEN), 0);
            break;
        case IFLA_BROADCAST: {
            ifla_broadcast_seen = true;
            ASSERT_EQ(memcmp(hw_broadcast_addr, RTA_DATA(attr), ETHER_ADDR_LEN), 0);
            break;
        }
        case IFLA_IFNAME: {
            ifla_name_seen = true;
            ASSERT_STREQ((char *)RTA_DATA(attr), name);
            break;
        }
        case IFLA_MTU: {
            ifla_mtu_seen = true;
            assert(*(int *)RTA_DATA(attr) == mtu);
            break;
        }
        case IFLA_QDISC: {
            ifla_qdisc_seen = true;
            ASSERT_STREQ((char *)RTA_DATA(attr), "noqueue");
            break;
        }
        case IFLA_STATS: {
            ifla_stats_seen = true;
            struct rtnl_link_stats *stats = (struct rtnl_link_stats *)RTA_DATA(attr);
            char *buf = (char *)stats;
            int i;
            for (i = 0; i < sizeof(struct rtnl_link_stats); i++) {
                ASSERT_EQ(buf[i], 0);
            }
            break;
        }
        default:
            FAIL(); //"Unknown flags!"
        }
    }
    ASSERT_TRUE(ifla_address_seen);
    ASSERT_TRUE(ifla_broadcast_seen);
    ASSERT_TRUE(ifla_name_seen);
    ASSERT_TRUE(ifla_mtu_seen);
    ASSERT_TRUE(ifla_qdisc_seen);
    ASSERT_TRUE(ifla_stats_seen);
    ASSERT_EQ(attr_count, 6);
}