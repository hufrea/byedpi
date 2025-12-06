#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <assert.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/socket.h>
#endif

#include "mpool.h"

#if defined(__linux__) || defined(_WIN32)
#define FAKE_SUPPORT 1
#define TIMEOUT_SUPPORT 1
#endif

#define OFFSET_END 1
#define OFFSET_MID 2
#define OFFSET_RAND 4
#define OFFSET_SNI 8
#define OFFSET_HOST 16
#define OFFSET_START 32

#define DETECT_HTTP_LOCAT 1
#define DETECT_TLS_ERR 2
#define DETECT_TORST 8

#define AUTO_RECONN 1
#define AUTO_POST 2
#define AUTO_SORT 4

#define FM_RAND 1
#define FM_ORIG 2

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_OOB,
    DESYNC_DISOOB,
    DESYNC_FAKE
};

#ifdef STR_MODE
static const char *demode_str[] = {
    "DESYNC_NONE",
    "DESYNC_SPLIT",
    "DESYNC_DISORDER",
    "DESYNC_OOB",
    "DESYNC_DISOOB",
    "DESYNC_FAKE"
};
#endif

union sockaddr_u {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
};

struct part {
    int m;
    int flag;
    long pos;
    int r, s;
};

struct packet {
     ssize_t size;
     char  *data;
     ssize_t off;
};

struct desync_params {
    int ttl;
    bool md5sig;
    struct packet fake_data;
    int udp_fake_count;
    struct part fake_offset;
    int fake_sni_count;
    const char **fake_sni_list;
    int fake_mod;
    int fake_tls_size;
    bool drop_sack;
    char oob_char[2];
    
    int parts_n;
    struct part *parts;
    
    int mod_http;
    int tlsrec_n;
    struct part *tlsrec;
    uint8_t tlsminor;
    bool tlsminor_set;
    
    int proto;
    int detect;
    struct mphdr *hosts;
    struct mphdr *ipset;
    uint16_t pf[2];
    int rounds[2];
    
    union sockaddr_u ext_socks;
    
    char *file_ptr;
    ssize_t file_size;
    
    int _optind;
    int id;
    uint64_t bit;
    int fail_count;
    int pri;
    const char *str;
    
    struct desync_params *prev;
    struct desync_params *next;
};

struct params {
    int dp_n;
    struct desync_params *dp;
    int await_int;
    bool wait_send;
    int def_ttl;
    bool custom_ttl;
    
    bool tfo;
    unsigned int timeout;
    int auto_level;
    int cache_ttl_n;
    unsigned int *cache_ttl;
    bool ipv6;
    bool resolve;
    bool udp;
    bool transparent;
    bool http_connect;
    int max_open;
    int debug;
    size_t bfsize;
    union sockaddr_u baddr;
    union sockaddr_u laddr;
    struct mphdr *mempool;
    
    const char *protect_path;
    const char *pid_file;
    int pid_fd;
    const char *cache_file;
};

extern struct params params;

extern struct packet fake_tls;
extern struct packet fake_http;
extern struct packet fake_udp;

#define ASSERT(exp) \
    char t[(exp) ? 1 : -1];
#endif
