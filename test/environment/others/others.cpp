#include <gtest/gtest.h>

extern "C" {
#include "netfuzzlib/module_api.h"
#include "module.h"
#include "environment/network_env.h"
#include "environment/interfaces.h"
}

class TestEnvironmentOthers : public ::testing::Test {
protected:
    void SetUp() override {
        init_main_library();
        load_config_file("config/network.conf");
    }
};

TEST_F(TestEnvironmentOthers, Add_network_device) {
    char hw_addr_lo[6] = { 0, 0, 0, 0, 0, 0 };
    unsigned int index;
    int err = nfl_add_l2_iface("klee_test", IFF_UP | IFF_LOOPBACK | IFF_RUNNING, 600, hw_addr_lo, hw_addr_lo, &index);
    ASSERT_EQ(err, 0);
    nfl_l2_iface_t *klee_test = get_l2_iface_by_index(index);
    ASSERT_TRUE(klee_test);
    ASSERT_STREQ(klee_test->name, "klee_test");
    ASSERT_EQ(if_nametoindex("klee_test"), klee_test->index);

    char test_device_name[IF_NAMESIZE];
    ASSERT_TRUE(if_indextoname(klee_test->index, test_device_name));
    ASSERT_STREQ(test_device_name, "klee_test");
}

TEST_F(TestEnvironmentOthers, if_indextoname) {
    char index_name[IFNAMSIZ];
    ASSERT_EQ(nullptr, if_indextoname(0, index_name));
    ASSERT_EQ(nullptr, if_indextoname(10, index_name));

    char *result;
    result = if_indextoname(3, index_name);
    ASSERT_EQ(nullptr, result);
}

TEST_F(TestEnvironmentOthers, if_nametoindex) {
    unsigned int result = if_nametoindex("lo");
    ASSERT_NE(result, 0);
    char index_name[IFNAMSIZ];
    if_indextoname(result, index_name);
    ASSERT_STREQ(index_name, "lo");
}
