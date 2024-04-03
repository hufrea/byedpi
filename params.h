#include <stdio.h>
#include <mpool.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

#if defined(__linux__) || defined(_WIN32)
#define FAKE_SUPPORT 1
#define TIMEOUT_SUPPORT 1
#endif
    
#define OFFSET_SNI 1
#define OFFSET_HOST 2

#define DETECT_HTTP_LOCAT 1
#define DETECT_HTTP_CLERR 2
#define DETECT_TLS_INVSID 4
#define DETECT_TLS_ALERT 8

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

struct desync_params {
    int ttl;
    char *ip_options;
    ssize_t ip_options_len;
    char md5sig;
    int parts_n;
    struct part *parts;
    int mod_http;
    int tlsrec_n;
    struct part *tlsrec;
    int detect;
};

struct params {
    char de_known;
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
    int max_open;
    int debug;
    size_t bfsize;
    struct sockaddr_in6 baddr;
    struct mphdr *mempool;
};

extern struct params params;

struct packet {
     ssize_t size;
     char  *data;
};
extern struct packet fake_tls;
extern struct packet fake_http;
extern struct packet oob_data;

extern char ip_option[1];