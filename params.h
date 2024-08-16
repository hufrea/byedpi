#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>
#include <stdio.h>

#include "mpool.h"

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <netinet/in.h>
    #include <unistd.h>
    #include <sys/socket.h>
#endif

#if defined(__linux__) || defined(_WIN32)
#define FAKE_SUPPORT 1
#define TIMEOUT_SUPPORT 1
#endif
    
#define OFFSET_SNI 1
#define OFFSET_HOST 2
#define OFFSET_END 3

#define DETECT_HTTP_LOCAT 1
#define DETECT_TLS_ERR 2
#define DETECT_TORST 8

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_OOB,
    DESYNC_DISOOB,
    DESYNC_FAKE
};

#ifdef STR_MODE
char *demode_str[] = {
    "DESYNC_NONE",
    "DESYNC_SPLIT",
    "DESYNC_DISORDER",
    "DESYNC_OOB",
    "DESYNC_DISOOB",
    "DESYNC_FAKE"
};
#endif

struct part {
    int m;
    int flag;
    long pos;
};

struct packet {
     ssize_t size;
     char  *data;
};

struct desync_params {
    int ttl;
    char *ip_options;
    ssize_t ip_options_len;
    char md5sig;
    struct packet fake_data;
    int udp_fake_count;
    int fake_offset;
    char drop_sack;
    char oob_char[2];
    
    int parts_n;
    struct part *parts;
    
    int mod_http;
    int tlsrec_n;
    struct part *tlsrec;
    
    int proto;
    int detect;
    struct mphdr *hosts;
    uint16_t pf[2];
    
    char *file_ptr;
    ssize_t file_size;
};

struct params {
    int dp_count;
    struct desync_params *dp;
    long sfdelay;
    char wait_send;
    int def_ttl;
    char custom_ttl;
    
    char tfo;
    unsigned int timeout;
    long cache_ttl;
    char ipv6;
    char resolve;
    char udp;
    int max_open;
    int debug;
    size_t bfsize;
    struct sockaddr_in6 baddr;
    struct sockaddr_in6 laddr;
    struct mphdr *mempool;
    
    char *protect_path;
};

extern struct params params;

extern struct packet fake_tls;
extern struct packet fake_http;
extern struct packet fake_udp;

extern char ip_option[1];
#endif
