#include "resolver.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "network_env.h"
#include "network_types.h"

static bool name_is_loopback_v4(const char *name) {
    return strcasecmp(name, "localhost") == 0 ||
           strcasecmp(name, "localhost.localdomain") == 0;
}

static bool name_is_loopback_v6(const char *name) {
    return strcasecmp(name, "ip6-localhost") == 0 ||
           strcasecmp(name, "ip6-loopback") == 0;
}

static bool find_iface_addr_by_text(const char *name, int family, nfl_addr_t *out) {
    network_env *env = get_network_env();
    char buf[INET6_ADDRSTRLEN];
    for (size_t i = 0; i < MAX_L2_INTERFACES; i++) {
        nfl_l2_iface_t *l2 = &env->l2_interfaces[i];
        if (l2->name[0] == '\0') {
            continue;
        }
        for (nfl_l3_iface_t *l3 = l2->l3_interfaces; l3 != NULL; l3 = l3->next) {
            if (!l3->addr) {
                continue;
            }
            if (family != AF_UNSPEC && l3->addr->s.sa_family != family) {
                continue;
            }
            if (l3->addr->s.sa_family == AF_INET) {
                inet_ntop(AF_INET, &l3->addr->s4.sin_addr, buf, sizeof(buf));
            } else if (l3->addr->s.sa_family == AF_INET6) {
                inet_ntop(AF_INET6, &l3->addr->s6.sin6_addr, buf, sizeof(buf));
            } else {
                continue;
            }
            if (strcmp(buf, name) == 0) {
                *out = *l3->addr;
                return true;
            }
        }
    }
    return false;
}

static bool resolve_loopback(int family, nfl_addr_t *out) {
    nfl_addr_t lo = { 0 };
    if (family == AF_INET) {
        lo.s4.sin_family = AF_INET;
        lo.s4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    } else {
        lo.s6.sin6_family = AF_INET6;
        lo.s6.sin6_addr = in6addr_loopback;
    }
    /* Only honour loopback if the model actually has it. */
    nfl_addr_t check;
    char text[INET6_ADDRSTRLEN] = { 0 };
    if (family == AF_INET) {
        inet_ntop(AF_INET, &lo.s4.sin_addr, text, sizeof(text));
    } else {
        inet_ntop(AF_INET6, &lo.s6.sin6_addr, text, sizeof(text));
    }
    if (!find_iface_addr_by_text(text, family, &check)) {
        return false;
    }
    *out = lo;
    return true;
}

static int parse_port(const char *service, uint16_t *out_port) {
    if (!service) {
        *out_port = 0;
        return 0;
    }
    char *end;
    const long v = strtol(service, &end, 10);
    if (*service != '\0' && *end == '\0') {
        if (v < 0 || v > 65535) {
            return EAI_SERVICE;
        }
        *out_port = (uint16_t)v;
        return 0;
    }
    struct servent *se = getservbyname(service, NULL);
    if (!se) {
        return EAI_SERVICE;
    }
    *out_port = ntohs((uint16_t)se->s_port);
    return 0;
}

int resolver_getaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res) {
    int family = hints ? hints->ai_family : AF_UNSPEC;
    int socktype = hints ? hints->ai_socktype : 0;
    int protocol = hints ? hints->ai_protocol : 0;
    int flags = hints ? hints->ai_flags : 0;

    if (family != AF_UNSPEC && family != AF_INET && family != AF_INET6) {
        return EAI_FAMILY;
    }

    uint16_t port = 0;
    const int srv_rc = parse_port(service, &port);
    if (srv_rc != 0) {
        return srv_rc;
    }

    nfl_addr_t resolved[2];
    int n_resolved = 0;

    if (!node) {
        if (family != AF_INET6) {
            nfl_addr_t a = { 0 };
            a.s4.sin_family = AF_INET;
            a.s4.sin_addr.s_addr = (flags & AI_PASSIVE) ? INADDR_ANY : htonl(INADDR_LOOPBACK);
            resolved[n_resolved++] = a;
        }
        if (family != AF_INET) {
            nfl_addr_t a = { 0 };
            a.s6.sin6_family = AF_INET6;
            if (flags & AI_PASSIVE) {
                a.s6.sin6_addr = in6addr_any;
            } else {
                a.s6.sin6_addr = in6addr_loopback;
            }
            resolved[n_resolved++] = a;
        }
    } else {
        nfl_addr_t a = { 0 };
        nfl_addr_t v4 = { 0 };
        nfl_addr_t v6 = { 0 };
        v4.s4.sin_family = AF_INET;
        v6.s6.sin6_family = AF_INET6;
        const bool numeric_v4 = inet_pton(AF_INET, node, &v4.s4.sin_addr) == 1;
        const bool numeric_v6 = inet_pton(AF_INET6, node, &v6.s6.sin6_addr) == 1;

        if (numeric_v4 && family != AF_INET6) {
            resolved[n_resolved++] = v4;
        } else if (numeric_v6 && family != AF_INET) {
            resolved[n_resolved++] = v6;
        } else if (numeric_v4 || numeric_v6) {
            return EAI_ADDRFAMILY;
        }

        if (n_resolved == 0 && (flags & AI_NUMERICHOST)) {
            return EAI_NONAME;
        }
        if (n_resolved == 0 && name_is_loopback_v4(node) && family != AF_INET6) {
            if (resolve_loopback(AF_INET, &a)) {
                resolved[n_resolved++] = a;
            }
        }
        if (n_resolved == 0 && (name_is_loopback_v4(node) || name_is_loopback_v6(node)) && family != AF_INET) {
            if (resolve_loopback(AF_INET6, &a)) {
                resolved[n_resolved++] = a;
            }
        }
        if (n_resolved == 0 && find_iface_addr_by_text(node, family, &a)) {
            resolved[n_resolved++] = a;
        }
        if (n_resolved == 0) {
            memset(&a, 0, sizeof(a));
            if (family != AF_INET6) {
                a.s4.sin_family = AF_INET;
                inet_pton(AF_INET, "1.2.3.4", &a.s4.sin_addr);
                resolved[n_resolved++] = a;
            }
            if (family != AF_INET) {
                memset(&a, 0, sizeof(a));
                a.s6.sin6_family = AF_INET6;
                inet_pton(AF_INET6, "2001:db8::1", &a.s6.sin6_addr);
                resolved[n_resolved++] = a;
            }
        }
    }

    struct addrinfo *head = NULL;
    struct addrinfo **tail = &head;
    for (int i = 0; i < n_resolved; i++) {
        struct addrinfo *ai = calloc(1, sizeof(*ai));
        if (!ai) {
            freeaddrinfo(head);
            return EAI_MEMORY;
        }
        ai->ai_flags = flags;
        ai->ai_family = resolved[i].s.sa_family;
        ai->ai_socktype = socktype;
        ai->ai_protocol = protocol;
        if (resolved[i].s.sa_family == AF_INET) {
            resolved[i].s4.sin_port = htons(port);
            ai->ai_addrlen = sizeof(struct sockaddr_in);
        } else {
            resolved[i].s6.sin6_port = htons(port);
            ai->ai_addrlen = sizeof(struct sockaddr_in6);
        }
        ai->ai_addr = malloc(ai->ai_addrlen);
        if (!ai->ai_addr) {
            free(ai);
            freeaddrinfo(head);
            return EAI_MEMORY;
        }
        memcpy(ai->ai_addr, &resolved[i], ai->ai_addrlen);

        if (i == 0 && node != NULL && (flags & AI_CANONNAME)) {
            ai->ai_canonname = strdup(node);
            if (!ai->ai_canonname) {
                free(ai->ai_addr);
                free(ai);
                freeaddrinfo(head);
                return EAI_MEMORY;
            }
        } else {
            ai->ai_canonname = NULL;
        }
        ai->ai_next = NULL;
        *tail = ai;
        tail = &ai->ai_next;
    }
    *res = head;
    return 0;
}

void resolver_freeaddrinfo(struct addrinfo *res) {
    while (res) {
        struct addrinfo *next = res->ai_next;
        free(res->ai_addr);
        free(res->ai_canonname);
        free(res);
        res = next;
    }
}

int resolver_getnameinfo(const struct sockaddr *sa, socklen_t salen,
                         char *host, socklen_t hostlen,
                         char *serv, socklen_t servlen, int flags) {
    if (!sa) {
        return EAI_FAMILY;
    }
    if (flags & NI_NAMEREQD) {
        return EAI_NONAME;
    }
    if (host && hostlen > 0) {
        if (sa->sa_family == AF_INET) {
            if (salen < (socklen_t)sizeof(struct sockaddr_in)) {
                return EAI_FAMILY;
            }
            const struct sockaddr_in *s4 = (const struct sockaddr_in *)sa;
            if (inet_ntop(AF_INET, &s4->sin_addr, host, hostlen) == NULL) {
                return EAI_OVERFLOW;
            }
        } else if (sa->sa_family == AF_INET6) {
            if (salen < (socklen_t)sizeof(struct sockaddr_in6)) {
                return EAI_FAMILY;
            }
            const struct sockaddr_in6 *s6 = (const struct sockaddr_in6 *)sa;
            if (inet_ntop(AF_INET6, &s6->sin6_addr, host, hostlen) == NULL) {
                return EAI_OVERFLOW;
            }
        } else {
            return EAI_FAMILY;
        }
    }
    if (serv && servlen > 0) {
        uint16_t port = 0;
        if (sa->sa_family == AF_INET) {
            port = ntohs(((const struct sockaddr_in *)sa)->sin_port);
        } else {
            port = ntohs(((const struct sockaddr_in6 *)sa)->sin6_port);
        }
        if (snprintf(serv, servlen, "%u", port) >= (int)servlen) {
            return EAI_OVERFLOW;
        }
    }
    return 0;
}

static __thread struct hostent t_he;
static __thread char t_he_name[NI_MAXHOST];
static __thread struct in_addr t_he_addr_v4;
static __thread struct in6_addr t_he_addr_v6;
static __thread char *t_he_addr_list[2];
static __thread char *t_he_aliases[1] = { NULL };
static __thread int t_h_errno;

int *resolver_h_errno_ptr(void) {
    return &t_h_errno;
}

struct hostent *resolver_gethostbyname2(const char *name, int af) {
    if (!name) {
        t_h_errno = HOST_NOT_FOUND;
        return NULL;
    }
    struct addrinfo hints = { 0 };
    hints.ai_family = af;
    hints.ai_flags = AI_NUMERICSERV;
    struct addrinfo *res = NULL;
    if (resolver_getaddrinfo(name, NULL, &hints, &res) != 0 || !res) {
        t_h_errno = HOST_NOT_FOUND;
        return NULL;
    }
    snprintf(t_he_name, sizeof(t_he_name), "%s", name);
    t_he.h_name = t_he_name;
    t_he.h_aliases = t_he_aliases;
    t_he.h_addrtype = res->ai_family;
    if (res->ai_family == AF_INET) {
        t_he_addr_v4 = ((struct sockaddr_in *)res->ai_addr)->sin_addr;
        t_he.h_length = sizeof(struct in_addr);
        t_he_addr_list[0] = (char *)&t_he_addr_v4;
    } else {
        t_he_addr_v6 = ((struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
        t_he.h_length = sizeof(struct in6_addr);
        t_he_addr_list[0] = (char *)&t_he_addr_v6;
    }
    t_he_addr_list[1] = NULL;
    t_he.h_addr_list = t_he_addr_list;
    resolver_freeaddrinfo(res);
    t_h_errno = 0;
    return &t_he;
}

struct hostent *resolver_gethostbyname(const char *name) {
    return resolver_gethostbyname2(name, AF_INET);
}
