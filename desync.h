#ifndef DESYNC_H
#define DESYNC_H

#include <stdint.h>
#include <stddef.h>

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <sys/socket.h>
#endif

ssize_t desync(int sfd, char *buffer, size_t bfsize, ssize_t n, ssize_t offset, struct sockaddr *dst, int dp_c);

ssize_t desync_udp(int sfd, char *buffer, size_t bfsize, ssize_t n, struct sockaddr *dst, int dp_c);

int get_family(struct sockaddr *dst);

int setttl(int fd, int ttl, int family);

struct tcpi {
    uint8_t state;
    uint8_t r[3];
    uint32_t rr[5];
    uint32_t unacked;
    uint32_t rrr[29];
    uint32_t notsent_bytes;
};

#endif
