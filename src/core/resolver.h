#ifndef NETFUZZLIB_RESOLVER_H
#define NETFUZZLIB_RESOLVER_H

#include <netdb.h>
#include <sys/socket.h>

int resolver_getaddrinfo(const char *node, const char *service,
                         const struct addrinfo *hints, struct addrinfo **res);
void resolver_freeaddrinfo(struct addrinfo *res);

int resolver_getnameinfo(const struct sockaddr *sa, socklen_t salen,
                         char *host, socklen_t hostlen,
                         char *serv, socklen_t servlen, int flags);

struct hostent *resolver_gethostbyname(const char *name);
struct hostent *resolver_gethostbyname2(const char *name, int af);

int *resolver_h_errno_ptr(void);

#endif // NETFUZZLIB_RESOLVER_H
