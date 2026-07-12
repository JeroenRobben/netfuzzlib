#ifndef NETFUZZLIB_LIBNL_H
#define NETFUZZLIB_LIBNL_H
#include <linux/netlink.h>
#include <stddef.h>
#include <stdint.h>

enum {
    NLE_NOMEM = 5,
    NLE_INVAL = 7,
};

struct nl_msg {
    struct nlmsghdr *nm_nlh;
    size_t nm_size;
    int nm_refcnt;
};

struct nl_msg *nlmsg_alloc();
void nlmsg_free(struct nl_msg *msg);

int nlmsg_append(struct nl_msg *n, const void *data, size_t len, int pad);
struct nlmsghdr *nlmsg_put(struct nl_msg *n, uint32_t pid, uint32_t seq, int type, int payload, int flags);
struct nlmsghdr *nlmsg_hdr(const struct nl_msg *n);

int nla_put(struct nl_msg *msg, int attrtype, int datalen, const void *data);

#endif // NETFUZZLIB_LIBNL_H
