#ifndef NETFUZZLIB_UDP_IPV4_H
#define NETFUZZLIB_UDP_IPV4_H

#define BLACKHOLE_HOST 0x08080808
#define BLACKHOLE_PORT 53

#define errx(code, fmt, ...) \
    do {                     \
        FAIL() << fmt;       \
    } while (0)

#define warn(...) \
    do {          \
    } while (0)

#define warnx(...) \
    do {           \
    } while (0)

#endif //NETFUZZLIB_UDP_IPV4_H
