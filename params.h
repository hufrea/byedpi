#ifndef PARAMS_H
#define PARAMS_H

#include <stdint.h>
#include <stdio.h>

#include "mpool.h"

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <unistd.h>
    #include <arpa/inet.h>
#endif

#ifdef __FreeBSD__
    #include <netinet/in.h>
#endif

#if defined(__linux__) || defined(_WIN32)
#define FAKE_SUPPORT 1
#define TIMEOUT_SUPPORT 1
#elif defined(__FreeBSD__)
#define FAKE_SUPPORT 1
// TIMEOUT_SUPPORT can't be used
#endif
    
#define OFFSET_SNI 1
#define OFFSET_HOST 2

#define DETECT_HTTP_LOCAT 1
#define DETECT_HTTP_CLERR 2
#define DETECT_TLS_INVSID 4
#define DETECT_TLS_ALERT 8
#define DETECT_TORST 16

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_OOB,
    DESYNC_FAKE
};

#ifdef STR_MODE
char *demode_str[] = {
    "DESYNC_NONE",
    "DESYNC_SPLIT",
    "DESYNC_DISORDER",
    "DESYNC_OOB",
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
extern struct packet oob_data;
extern struct packet fake_udp;

extern char ip_option[1];

#endif
