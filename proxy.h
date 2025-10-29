#ifndef PROXY_H
#define PROXY_H

#include <stdint.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <sys/socket.h>
#endif

#include "conev.h"

#define SA_SIZE(s) \
    (((const struct sockaddr *)s)->sa_family == AF_INET6) ? \
        sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)

#pragma pack(push, 1)

struct s4_req {
    uint8_t ver, cmd;
    uint16_t port;
    struct in_addr i4;
};

struct s5_req {
    uint8_t ver, cmd, zero, atp;
    union {
        struct {
            struct in_addr ip;
            uint16_t port;
        } i4;
        struct {
            struct in6_addr ip;
            uint16_t port;
        } i6;
        struct {
            uint8_t len;
            char domain[257];
        } id;
    } dst;
};

struct s5_rep {
    uint8_t ver, code, zero, atp;
    struct {
        struct in_addr i4;
        uint16_t port;
    } addr;
};

#pragma pack(pop)

#define S_AUTH_NONE 0x00
#define S_AUTH_BAD 0xff

#define S_ATP_I4 0x01
#define S_ATP_ID 0x03
#define S_ATP_I6 0x04

#define S_CMD_CONN 0x01
#define S_CMD_BIND 0x02
#define S_CMD_AUDP 0x03

#define S_ER_OK 0x00
#define S_ER_GEN 0x01
#define S_ER_DENY 0x02
#define S_ER_NET 0x03
#define S_ER_HOST 0x04
#define S_ER_CONN 0x05
#define S_ER_TTL 0x06
#define S_ER_CMD 0x07
#define S_ER_ATP 0x08

#define S4_OK 0x5a
#define S4_ER 0x5b

#define S_VER5 0x05
#define S_VER4 0x04

#define S_SIZE_MIN 8
#define S_SIZE_I4 10
#define S_SIZE_I6 22
#define S_SIZE_ID 7

void map_fix(union sockaddr_u *addr, char f6);

int create_conn(struct poolhd *pool,
        struct eval *val, const union sockaddr_u *dst, evcb_t next);

int s5_set_addr(char *buffer, size_t n,
        const union sockaddr_u *addr, char end);

int listen_socket(const union sockaddr_u *srv);

int on_tunnel(struct poolhd *pool, struct eval *val, int etype);

int on_udp_tunnel(struct poolhd *pool, struct eval *val, int et);

int on_request(struct poolhd *pool, struct eval *val, int et);

int on_connect(struct poolhd *pool, struct eval *val, int et);

int on_ignore(struct poolhd *pool, struct eval *val, int etype);

int start_event_loop(int srvfd);

int run(const union sockaddr_u *srv);

#endif
