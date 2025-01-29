#ifndef EXTEND_H
#define EXTEND_H

#include <stddef.h>

#include "proxy.h"

int socket_mod(int fd);

int connect_hook(struct poolhd *pool, struct eval *val, 
        const union sockaddr_u *dst, evcb_t next);
        
ssize_t tcp_send_hook(struct poolhd *pool, 
        struct eval *remote, struct buffer *buff, ssize_t n);
        
ssize_t tcp_recv_hook(struct poolhd *pool, 
        struct eval *val, struct buffer *buff);
        
ssize_t udp_hook(struct eval *val, 
        char *buffer, ssize_t n, const union sockaddr_u *dst);

int on_first_tunnel(struct poolhd *pool, struct eval *val, int etype);
        
#ifdef __linux__
static int protect(int conn_fd, const char *path);
#else
#define protect(fd, path) 0
#endif

#endif
