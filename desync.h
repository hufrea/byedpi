#ifndef DESYNC_H
#define DESYNC_H

#include <stdint.h>
#include <stddef.h>

#include "conev.h"

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/socket.h>
#endif

ssize_t desync(struct poolhd *pool, struct eval *val, struct buffer *buff, ssize_t *n, bool *wait);

ssize_t desync_udp(int sfd, char *buffer, ssize_t n, const struct sockaddr *dst, int dp_c);

int setttl(int fd, int ttl);

int pre_desync(int sfd, int dp_c);

int post_desync(int sfd, int dp_c);

struct proto_info {
    char init, type;
    int host_len, host_pos;
};

static long gen_offset(long pos, int flag,
        const char *buffer, size_t n, long lp, struct proto_info *info);
#endif
