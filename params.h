#include <stdio.h>
#include <mpool.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

#define OFFSET_SNI 1
#define OFFSET_HOST 2

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_OOB,
    DESYNC_FAKE
};

struct part {
    int m;
    int flag;
    long pos;
};

struct desync_params {
    int ttl;
    int parts_n;
    struct part *parts;
    int mod_http;
    int tlsrec_n;
    struct part *tlsrec;
};

struct params {
    char de_known;
    int dp_count;
    struct desync_params *dp;
    long sfdelay;
    int def_ttl;
    char custom_ttl;
    
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
