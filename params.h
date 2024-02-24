#include <stdio.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
#endif

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
    char tlsrec;
    int tlsrec_pos;
    char tlsrec_sni;
    
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
