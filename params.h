#include <stdio.h>
#include <arpa/inet.h>

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_FAKE
};

struct params {
    char de_known;
    int ttl;
    int split;
    size_t sfdelay;
    enum demode attack;
    char split_host;
    int def_ttl;
    char custom_ttl;
    int mod_http;
    
    char ipv6;
    char resolve;
    int max_open;
    int debug;
    size_t bfsize;
    struct sockaddr_in6 baddr;
};

extern struct params params;

struct packet {
     ssize_t size;
     char  *data;
};
extern struct packet fake_tls;
extern struct packet fake_http;

#define LOG_S 1
#define LOG_L 2

#define LOG(s, str, ...) \
    if (params.debug >= s) printf(str, ##__VA_ARGS__)
    
