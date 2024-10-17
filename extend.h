#ifndef EXTEND_H
#define EXTEND_H

#include <stddef.h>

#include "proxy.h"

int socket_mod(int fd, struct sockaddr *dst);

int connect_hook(struct poolhd *pool, struct eval *val, 
        struct sockaddr_ina *dst, int next);
        
ssize_t tcp_send_hook(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, ssize_t n);
        
ssize_t tcp_recv_hook(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize);
        
ssize_t udp_hook(struct eval *val, 
        char *buffer, size_t bfsize, ssize_t n, struct sockaddr_ina *dst);

#ifdef __linux__
int protect(int conn_fd, const char *path);
#else
#define protect(fd, path) 0
#endif

#endif
