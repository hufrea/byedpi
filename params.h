#include <stdio.h>

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_FAKE
};

#define DESYNC_UDP_FAKE 1

struct params {
    int ttl;
    int split;
    size_t sfdelay;
    enum demode attack;
    int desync_udp;
    char split_host;
    int def_ttl;
    int mod_http;
    
    char ipv6;
    char resolve;
    char udp;
    char de_known;
    int max_open;
    
    int debug;
    size_t bfsize;
    int send_bfsz;
};

extern struct params params;

struct packet {
    ssize_t size;
    char  *data;
};
extern struct packet fake_tls;
extern struct packet fake_http;
extern struct packet fake_udp;

#define LOG_S 1
#define LOG_L 2

#define LOG(s, str, ...) \
    if (params.debug >= s) printf(str, ##__VA_ARGS__)
