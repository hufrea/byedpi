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
    (((struct sockaddr *)s)->sa_family == AF_INET6) ? \
        sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in)

struct sockaddr_ina {
    union {
        struct sockaddr sa;
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
};

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
            struct in_addr i4;
            uint16_t p4;
        };
        struct {
            struct in6_addr i6;
            uint16_t p6;
        };
        struct {
            uint8_t len;
            char domain[];
        } id;
    };
};

struct s5_rep {
    uint8_t ver, code, zero, atp;
    struct {
        struct in_addr i4;
        uint16_t port;
    };
};

#pragma pack(pop)

enum s_auth {
    S_AUTH_NONE = 0x00,
    S_AUTH_GSSAPI = 0x01,
    S_AUTH_USPA = 0x02,
    S_AUTH_BAD = 0xff
};

enum s_atp {
    S_ATP_I4 = 0x01,
    S_ATP_ID = 0x03,
    S_ATP_I6 = 0x04
};

enum s_cmd {
    S_CMD_CONN = 0x01,
    S_CMD_BIND = 0x02,
    S_CMD_AUDP = 0x03
};

enum s_err {
    S_ER_OK = 0x00,
    S_ER_GEN = 0x01,
    S_ER_DENY = 0x02,
    S_ER_NET = 0x03,
    S_ER_HOST = 0x04,
    S_ER_CONN = 0x05,
    S_ER_TTL = 0x06,
    S_ER_CMD = 0x07,
    S_ER_ATP = 0x08
};

enum s4_rep {
    S4_OK = 0x5a,
    S4_ER = 0x5b
};

#define S_VER5 0x05
#define S_VER4 0x04

#define S_SIZE_MIN 8
#define S_SIZE_I4 10
#define S_SIZE_I6 22
#define S_SIZE_ID 7

void map_fix(struct sockaddr_ina *addr, char f6);

int resp_error(int fd, int e, int flag);

int create_conn(struct poolhd *pool,
        struct eval *val, struct sockaddr_ina *dst, int next);

int on_tunnel(struct poolhd *pool, struct eval *val, 
        char *buffer, size_t bfsize, int out);
        
int listen_socket(struct sockaddr_ina *srv);

int event_loop(int srvfd);

int run(struct sockaddr_ina *srv);

#endif
