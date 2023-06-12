#include <stdio.h>

enum mode {
    MODE_PROXY_H,
    MODE_PROXY_S,
    MODE_TRANSPARENT
};

enum demode {
    DESYNC_NONE,
    DESYNC_SPLIT,
    DESYNC_DISORDER,
    DESYNC_FAKE
};

struct params {
    int ttl;
    int split;
    size_t sfdelay;
    enum demode attack;
    char split_host;
    int def_ttl;
    int mod_http;
    
    enum mode mode;
    char ipv6;
    char resolve;
    char de_known;
    int max_open;
    
    int debug;
    size_t bfsize;
    size_t nack_max;
    int send_bfsz;
};

extern struct params params;

struct packet {
    size_t size;
    char  *data;
};
extern struct packet fake_tls;
extern struct packet fake_http;

#define LOG_S 1
#define LOG_L 2

#define LOG(s, str, ...) \
    if (params.debug >= s) printf(str, ##__VA_ARGS__)