#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#include <params.h>
#include <proxy.h>
#include <packets.h>
#include <error.h>

#ifndef _WIN32
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <fcntl.h>

    #define FAKE_SUPPORT 1
#else
    #include <ws2tcpip.h>
    #define close(fd) closesocket(fd)
#endif

#define VERSION 4


struct packet fake_tls = { 
    sizeof(tls_data), tls_data 
},
fake_http = { 
    sizeof(http_data), http_data
},
oob_data = { 
    1, "a"
};



struct params params = {
    .ttl = 8,
    .parts_n = 0,
    .parts = 0,
    .sfdelay = 3,
    .def_ttl = 0,
    .custom_ttl = 0,
    .mod_http = 0,
    .tlsrec = 0,
    .tlsrec_n = 0,
    .de_known = 0,
    
    .ipv6 = 1,
    .resolve = 1,
    .max_open = 512,
    .bfsize = 16384,
    .baddr = {
        .sin6_family = AF_INET6
    },
    .debug = 0
};


const char help_text[] = {
    "    -i, --ip, <ip>            Listening IP, default 0.0.0.0\n"
    "    -p, --port <num>          Listening port, default 1080\n"
    "    -c, --max-conn <count>    Connection count limit, default 512\n"
    "    -N, --no-domain           Deny domain resolving\n"
    "    -I  --conn-ip <ip>        Connection binded IP, default ::\n"
    "    -b, --buf-size <size>     Buffer size, default 16384\n"
    "    -x, --debug               Print logs, 0, 1 or 2\n"
    "    -g, --def-ttl <num>       TTL for all outgoing connections\n"
    // desync options
    "    -K, --desync-known        Desync only HTTP and TLS with SNI\n"
    "    -s, --split <n[+s]>       Split packet at n, +s to add SNI offset\n"
    "    -s, --disorder <n[+s]>    Split and send reverse order\n"
    "    -o, --oob <n[+s]>         Split and send as OOB data\n"
    #ifdef FAKE_SUPPORT
    "    -f, --fake <n[+s]>        Split and send fake packet\n"
    "    -t, --ttl <num>           TTL of fake packets, default 8\n"
    "    -l, --fake-tls <file>\n"
    "    -j, --fake-http <file>    Set custom fake packet\n"
    "    -n, --tls-sni <str>       Change SNI in fake CH\n"
    #endif
    "    -e, --oob-data <file>     Set custom OOB data\n"
    "    -M, --mod-http <h,d,r>    Modify http: hcsmix,dcsmix,rmspace\n"
    "    -r, --tlsrec <n[+s]>      Make TLS record at offset\n"
};


const struct option options[] = {
    {"no-domain",     0, 0, 'N'},
    {"no-ipv6",       0, 0, 'X'},
    {"help",          0, 0, 'h'},
    {"version",       0, 0, 'v'},
    {"ip",            1, 0, 'i'},
    {"port",          1, 0, 'p'},
    {"conn-ip",       1, 0, 'I'},
    {"buf-size",      1, 0, 'b'},
    {"max-conn",      1, 0, 'c'},
    {"debug",         1, 0, 'x'},
    
    {"desync-known ", 0, 0, 'K'},
    {"split",         1, 0, 's'},
    {"disorder",      1, 0, 'd'},
    {"oob",           1, 0, 'o'},
    #ifdef FAKE_SUPPORT
    {"fake",          1, 0, 'f'},
    {"ttl",           1, 0, 't'},
    {"fake-tls",      1, 0, 'l'},
    {"fake-http",     1, 0, 'j'},
    {"tls-sni",       1, 0, 'n'},
    #endif
    {"oob-data",      1, 0, 'e'},
    {"mod-http",      1, 0, 'M'},
    {"tlsrec",        1, 0, 'r'},
    {"def-ttl",       1, 0, 'g'},
    {"delay",         1, 0, 'w'}, //
    
    {0}
};
    

char *ftob(char *name, ssize_t *sl)
{
    char *buffer = 0;
    long size;
    
    FILE *file = fopen(name, "rb");
    if (!file)
        return 0;
    do {
        if (fseek(file, 0, SEEK_END)) {
            break;
        }
        size = ftell(file);
        if (!size || fseek(file, 0, SEEK_SET)) {
            break;
        }
        if (!(buffer = malloc(size))) {
            break;
        }
        if (fread(buffer, 1, size, file) != size) {
            free(buffer);
            buffer = 0;
        }
    } while (0);
    if (buffer) {
        *sl = size;
    }
    fclose(file);
    return buffer;
}


int get_addr(const char *str, struct sockaddr_ina *addr)
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    
    if (getaddrinfo(str, 0, &hints, &res) || !res) {
        return -1;
    }
    if (res->ai_addr->sa_family == AF_INET6)
        addr->in6 = *(struct sockaddr_in6 *)res->ai_addr;
    else
        addr->in = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    return 0;
}


int get_default_ttl()
{
    int orig_ttl = -1, fd;
    socklen_t tsize = sizeof(orig_ttl);
    
    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        uniperror("socket");
        return -1;
    }
    if (getsockopt(fd, IPPROTO_IP, IP_TTL,
             (char *)&orig_ttl, &tsize) < 0) {
        uniperror("getsockopt IP_TTL");
    }
    close(fd);
    return orig_ttl;
}


struct part *add_part(struct part **root, int *n)
{
    struct part *p = realloc(
        *root, sizeof(struct part) * (*n + 1));
    if (!p) {
        uniperror("realloc");
        return 0;
    }
    *root = p;
    *n = *n + 1;
    return &((*root)[(*n) - 1]);
}


int parse_offset(struct part *part, const char *str)
{
    char *end = 0;
    long val = strtol(str, &end, 0);
    if (*end == '+') switch (*(end + 1)) {
        case 's': 
            part->flag = OFFSET_SNI;
            break;
        case 'h': 
            part->flag = OFFSET_HOST;
            break;
        default:
            return -1;
    }
    else if (*end) {
        return -1;
    }
    part->pos = val;
    return 0;
}


int main(int argc, char **argv) 
{
    #ifdef _WIN32
    WSADATA wsa;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
        uniperror("WSAStartup");
        return -1;
    }
    #endif
    struct sockaddr_ina s = {
        .in = {
            .sin_family = AF_INET,
            .sin_port = htons(1080)
    }},
    b = { .in6 = params.baddr };
    
    int optc = sizeof(options)/sizeof(*options);
    for (int i = 0, e = optc; i < e; i++)
        optc += options[i].has_arg;
        
    char opt[optc + 1];
    opt[optc] = 0;
    
    for (int i = 0, o = 0; o < optc; i++, o++) {
        opt[o] = options[i].val;
        for (int c = options[i].has_arg; c; c--) {
            o++;
            opt[o] = ':';
        }
    }
    
    int rez;
    int invalid = 0;
    
    long val = 0;
    char *end = 0;
    uint16_t port = htons(1080);
    
    while (!invalid && (rez = getopt_long_only(
             argc, argv, opt, options, 0)) != -1) {
        switch (rez) {
        
        case 'N':
            params.resolve = 0;
            break;
        case 'X':
            params.ipv6 = 0;
            break;
        case 'h':
            printf(help_text);
            return 0;
        case 'v':
            printf("%d\n", VERSION);
            return 0;
        
        case 'i':
            if (get_addr(optarg, &s) < 0)
                invalid = 1;
            break;
            
        case 'p':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 0xffff || *end)
                invalid = 1;
            else
                port = htons(val);
            break;
            
        case 'I':
            if (get_addr(optarg, &b) < 0)
                invalid = 1;
            else
                params.baddr = b.in6;
            break;
            
        case 'b':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > INT_MAX/4 || *end)
                invalid = 1;
            else
                params.bfsize = val;
            break;
            
        case 'c':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val >= (0xffff/2) || *end) 
                invalid = 1;
            else
                params.max_open = val;
            break;
           
        case 'x': //
            params.debug = strtol(optarg, 0, 0);
            if (params.debug < 0)
                invalid = 1;
            break;
            
        // desync options
        
        case 'K':
            params.de_known = 1;
            break;
            
        case 's':
        case 'd':
        case 'o':
        case 'f':
            ;
            struct part *part = add_part(
                &params.parts, &params.parts_n);
            if (!part) {
                return -1;
            }
            if (parse_offset(part, optarg)) {
                invalid = 1;
                break;
            }
            switch (rez) {
                case 's': part->m = DESYNC_SPLIT;
                    break;
                case 'd': part->m = DESYNC_DISORDER;
                    break;
                case 'o': part->m = DESYNC_OOB;
                    break;
                case 'f': part->m = DESYNC_FAKE;
            }
            break;
            
        case 't':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 255 || *end) 
                invalid = 1;
            else
                params.ttl = val;
            break;
            
        case 'n':
            if (change_tls_sni(optarg, fake_tls.data, fake_tls.size)) {
                fprintf(stderr, "error chsni\n");
                return -1;
            }
            printf("sni: %s\n", optarg);
            break;
            
        case 'l':
            fake_tls.data = ftob(optarg, &fake_tls.size);
            if (!fake_tls.data) {
                uniperror("read file");
                return -1;
            }
            break;
            
        case 'j':
            fake_http.data = ftob(optarg, &fake_http.size);
            if (!fake_http.data) {
                uniperror("read file");
                return -1;
            }
            break;
            
        case 'e':
            oob_data.data = ftob(optarg, &oob_data.size);
            if (!oob_data.data) {
                uniperror("read file");
                return -1;
            }
            break;
            
        case 'M':
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case 'r': 
                        params.mod_http |= MH_SPACE;
                        break;
                    case 'h': 
                        params.mod_http |= MH_HMIX;
                        break;
                    case 'd': 
                        params.mod_http |= MH_DMIX;
                        break;
                    default:
                        invalid = 1;
                        continue;
                }
                end = strchr(end, ',');
                if (end) end++;
            }
            break;
            
        case 'r':
            part = add_part(&params.tlsrec, &params.tlsrec_n);
            if (!part) {
                return -1;
            }
            if (parse_offset(part, optarg)
                   || part->pos > 0xffff) {
                invalid = 1;
                break;
            }
            break;
            
        case 'g':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 255 || *end)
                invalid = 1;
            else {
                params.def_ttl = val;
                params.custom_ttl = 1;
            }
            break;
            
        case 'w': //
            params.sfdelay = strtol(optarg, &end, 0);
            if (params.sfdelay < 0 || optarg == end 
                    || params.sfdelay >= 1000 || *end)
                invalid = 1;
            break;
            
            
        case 0:
            break;
            
        case '?':
            return -1;
            
        default: 
            printf("?: %c\n", rez);
            return -1;
        }
    }
    if (invalid) {
        fprintf(stderr, "invalid value: -%c %s\n", rez, optarg);
        return -1;
    }
    s.in.sin_port = port;
    b.in.sin_port = 0;
    
    if (b.sa.sa_family != AF_INET6) {
        params.ipv6 = 0;
    }
    if (!params.def_ttl) {
        if ((params.def_ttl = get_default_ttl()) < 1) {
            return -1;
        }
    }
    int status = run(&s);
    #ifdef _WIN32
    WSACleanup();
    #endif
    return status;
}
