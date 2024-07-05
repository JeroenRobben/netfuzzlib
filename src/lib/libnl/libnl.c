#include "libnl.h"
#include <string.h>

static size_t default_msg_size = 4096;

/**
 * Calculates size of netlink message based on payload length.
 * @arg payload		Length of payload
 *
 * @return size of netlink message without padding.
 */
int nlmsg_size(int payload) {
    return NLMSG_HDRLEN + payload;
}

static int nlmsg_msg_size(int payload) {
    return nlmsg_size(payload);
}

/**
 * Calculates size of netlink message including padding based on payload length
 * @arg payload		Length of payload
 *
 * This function is idential to nlmsg_size() + nlmsg_padlen().
 *
 * @return Size of netlink message including padding.
 */
int nlmsg_total_size(int payload) {
    return NLMSG_ALIGN(nlmsg_msg_size(payload));
}

/**
 * Allocate a new netlink message with the default maximum payload size.
 *
 * Allocates a new netlink message without any further payload. The
 * maximum payload size defaults to PAGESIZE or as otherwise specified
 * with nlmsg_set_default_size().
 *
 * @return Newly allocated netlink message or NULL.
 */
struct nl_msg *nlmsg_alloc(void) {
    struct nl_msg *nm = calloc(1, sizeof(*nm));
    if (!nm)
        goto errout;

    nm->nm_refcnt = 1;

    nm->nm_nlh = calloc(1, default_msg_size);
    if (!nm->nm_nlh)
        goto errout;

    nm->nm_size = default_msg_size;
    nm->nm_nlh->nlmsg_len = nlmsg_total_size(0);

    return nm;
errout:
    free(nm);
    return NULL;
}

/**
 * Release a reference from an netlink message
 * @arg msg		message to release reference from
 *
 * Frees memory after the last reference has been released.
 */
void nlmsg_free(struct nl_msg *msg) {
    if (!msg)
        return;

    msg->nm_refcnt--;

    if (msg->nm_refcnt <= 0) {
        free(msg->nm_nlh);
        free(msg);
    }
}

/**
 * Return actual netlink message
 * @arg n		netlink message
 *
 * Returns the actual netlink message casted to the type of the netlink
 * message header.
 *
 * @return A pointer to the netlink message.
 */
struct nlmsghdr *nlmsg_hdr(struct nl_msg *n) {
    return n->nm_nlh;
}

void *nlmsg_tail(const struct nlmsghdr *nlh) {
    return (unsigned char *)nlh + NLMSG_ALIGN(nlh->nlmsg_len);
}

/**
 * Reserve room for additional data in a netlink message
 * @arg n		netlink message
 * @arg len		length of additional data to reserve room for
 * @arg pad		number of bytes to align data to
 *
 * Reserves room for additional data at the tail of the an
 * existing netlink message. Eventual padding required will
 * be zeroed out.
 *
 * @return Pointer to start of additional data tailroom or NULL.
 */
void *nlmsg_reserve(struct nl_msg *n, size_t len, int pad) {
    char *buf = (char *)n->nm_nlh;
    size_t nlmsg_len = n->nm_nlh->nlmsg_len;
    size_t tlen;

    if (len > n->nm_size)
        return NULL;

    tlen = pad ? ((len + (pad - 1)) & ~(pad - 1)) : len;

    if ((tlen + nlmsg_len) > n->nm_size)
        return NULL;

    buf += nlmsg_len;
    n->nm_nlh->nlmsg_len += tlen;

    if (tlen > len)
        memset(buf + len, 0, tlen - len);

    return buf;
}

/**
 * Add a netlink message header to a netlink message
 * @arg n		netlink message
 * @arg pid		netlink process id or NL_AUTO_PID
 * @arg seq		sequence number of message or NL_AUTO_SEQ
 * @arg type		message type
 * @arg payload		length of message payload
 * @arg flags		message flags
 *
 * Adds or overwrites the netlink message header in an existing message
 * object. If \a payload is greater-than zero additional room will be
 * reserved, f.e. for family specific headers. It can be accesed via
 * nlmsg_data().
 *
 * @return A pointer to the netlink message header or NULL.
 */
struct nlmsghdr *nlmsg_put(struct nl_msg *n, uint32_t pid, uint32_t seq, int type, int payload, int flags) {
    struct nlmsghdr *nlh;

    nlh = (struct nlmsghdr *)n->nm_nlh;
    nlh->nlmsg_type = type;
    nlh->nlmsg_flags = flags;
    nlh->nlmsg_pid = pid;
    nlh->nlmsg_seq = seq;

    if (payload > 0 && nlmsg_reserve(n, payload, NLMSG_ALIGNTO) == NULL)
        return NULL;

    return nlh;
}

/**
 * Append data to tail of a netlink message
 * @arg n		netlink message
 * @arg data		data to add
 * @arg len		length of data
 * @arg pad		Number of bytes to align data to.
 *
 * Extends the netlink message as needed and appends the data of given
 * length to the message.
 *
 * @return 0 on success or a negative error code
 */
int nlmsg_append(struct nl_msg *n, void *data, size_t len, int pad) {
    void *tmp;

    tmp = nlmsg_reserve(n, len, pad);
    if (tmp == NULL)
        return -NLE_NOMEM;

    memcpy(tmp, data, len);

    return 0;
}

/**
 * Return size of attribute whithout padding.
 * @arg payload		Payload length of attribute.
 *
 * @code
 *    <-------- nla_attr_size(payload) --------->
 *   +------------------+- - -+- - - - - - - - - +- - -+
 *   | Attribute Header | Pad |     Payload      | Pad |
 *   +------------------+- - -+- - - - - - - - - +- - -+
 * @endcode
 *
 * @return Size of attribute in bytes without padding.
 */
int nla_attr_size(int payload) {
    return NLA_HDRLEN + payload;
}

/**
 * Return size of attribute including padding.
 * @arg payload		Payload length of attribute.
 *
 * @code
 *    <----------- nla_total_size(payload) ----------->
 *   +------------------+- - -+- - - - - - - - - +- - -+
 *   | Attribute Header | Pad |     Payload      | Pad |
 *   +------------------+- - -+- - - - - - - - - +- - -+
 * @endcode
 *
 * @return Size of attribute in bytes.
 */
int nla_total_size(int payload) {
    return NLA_ALIGN(nla_attr_size(payload));
}

/**
 * Return length of padding at the tail of the attribute.
 * @arg payload		Payload length of attribute.
 *
 * @code
 *   +------------------+- - -+- - - - - - - - - +- - -+
 *   | Attribute Header | Pad |     Payload      | Pad |
 *   +------------------+- - -+- - - - - - - - - +- - -+
 *                                                <--->
 * @endcode
 *
 * @return Length of padding in bytes.
 */
int nla_padlen(int payload) {
    return nla_total_size(payload) - nla_attr_size(payload);
}

/**
 * Reserve space for a attribute.
 * @arg msg		Netlink Message.
 * @arg attrtype	Attribute Type.
 * @arg attrlen		Length of payload.
 *
 * Reserves room for a attribute in the specified netlink message and
 * fills in the attribute header (type, length). Returns NULL if there
 * is unsuficient space for the attribute.
 *
 * Any padding between payload and the start of the next attribute is
 * zeroed out.
 *
 * @return Pointer to start of attribute or NULL on failure.
 */
struct nlattr *nla_reserve(struct nl_msg *msg, int attrtype, int attrlen) {
    struct nlattr *nla;
    int tlen;

    if (attrlen < 0)
        return NULL;

    tlen = NLMSG_ALIGN(msg->nm_nlh->nlmsg_len) + nla_total_size(attrlen);

    if (tlen > msg->nm_size)
        return NULL;

    nla = (struct nlattr *)nlmsg_tail(msg->nm_nlh);
    nla->nla_type = attrtype;
    nla->nla_len = nla_attr_size(attrlen);

    if (attrlen)
        memset((unsigned char *)nla + nla->nla_len, 0, nla_padlen(attrlen));
    msg->nm_nlh->nlmsg_len = tlen;

    return nla;
}

/**
 * Return pointer to the payload section.
 * @arg nla		Attribute.
 *
 * @return Pointer to start of payload section.
 */
void *nla_data(const struct nlattr *nla) {
    return (char *)nla + NLA_HDRLEN;
}

/**
 * Add a unspecific attribute to netlink message.
 * @arg msg		Netlink message.
 * @arg attrtype	Attribute type.
 * @arg datalen		Length of data to be used as payload.
 * @arg data		Pointer to data to be used as attribute payload.
 *
 * Reserves room for a unspecific attribute and copies the provided data
 * into the message as payload of the attribute. Returns an error if there
 * is insufficient space for the attribute.
 *
 * @see nla_reserve
 * @return 0 on success or a negative error code.
 */
int nla_put(struct nl_msg *msg, int attrtype, int datalen, const void *data) {
    struct nlattr *nla;

    nla = nla_reserve(msg, attrtype, datalen);
    if (!nla) {
        if (datalen < 0)
            return -NLE_INVAL;

        return -NLE_NOMEM;
    }

    if (datalen > 0) {
        memcpy(nla_data(nla), data, datalen);
    }

    return 0;
}