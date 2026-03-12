#ifndef RESOLVE_H
#define RESOLVE_H

#include "params.h"

int resolve_system(const char *hostname, int len, union sockaddr_u *addr_out);

int resolve_plain(const char *hostname, int len, union sockaddr_u *addr_out);

int resolve_dot(const char *hostname, int len, union sockaddr_u *addr_out);

int resolve(const char *hostname, int len, union sockaddr_u *addr_out);

#endif
