#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>

#include <params.h>
#include <proxy.h>
#include <packets.h>

#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>


#define FAKE_SUPPORT 1

#define VERSION 3


struct packet fake_tls = { 
    sizeof(tls_data), tls_data 
},
fake_http = { 
    sizeof(http_data), http_data
};


struct params params = {
    .ttl = 8,
    .split = 3,
    .sfdelay = 3000,
    .attack = DESYNC_NONE,
    .split_host = 0,
    .def_ttl = 0,
    .custom_ttl = 0,
    .mod_http = 0,
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
    "    -D, --daemon              Daemonize\n"
    "    -f, --pidfile <file>      Write pid to file\n"
    "    -c, --max-conn <count>    Connection count limit, default 512\n"
    "    -N, --no-domain           Deny domain resolving\n"
    "    -I  --conn-ip <ip>        Connection binded IP, default ::\n"
    "    -b, --buf-size <size>     Buffer size, default 16384\n"
    "    -x, --debug               Print logs, 0, 1 or 2\n"
    "    -g, --def-ttl <num>       TTL for all outgoing connections\n"
    // desync options
    "    -K, --desync-known        Desync only HTTP and TLS with SNI\n"
    #ifdef FAKE_SUPPORT
    "    -m, --method <s|d|f>      Desync method: split,disorder,fake\n"
    #else
    "    -m, --method <s|d>        Desync method: split,disorder\n"
    #endif
    "    -s, --split-pos <offset>  Split position, default 3\n"
    "    -H, --split-at-host       Add Host/SNI offset to split position\n"
    #ifdef FAKE_SUPPORT
    "    -t, --ttl <num>           TTL of fake packets, default 8\n"
    "    -l, --fake-tls <file>\n"
    "    -o, --fake-http <file>    Set custom fake packet\n"
    "    -n, --tls-sni <str>       Change SNI in fake CH\n"
    #endif
    "    -M, --mod-http <h,d,r>    Modify http: hcsmix,dcsmix,rmspace\n"
};


const struct option options[] = {
    {"daemon",        0, 0, 'D'},
    {"no-domain",     0, 0, 'N'},
    {"no-ipv6",       0, 0, 'X'},
    {"help",          0, 0, 'h'},
    {"version",       0, 0, 'v'},
    {"pidfile",       1, 0, 'f'},
    {"ip",            1, 0, 'i'},
    {"port",          1, 0, 'p'},
    {"conn-ip",       1, 0, 'I'},
    {"buf-size",      1, 0, 'b'},
    {"max-conn",      1, 0, 'c'},
    {"debug",         1, 0, 'x'},
    
    {"desync-known ", 0, 0, 'K'},
    {"split-at-host", 0, 0, 'H'},
    {"method",        1, 0, 'm'},
    {"split-pos",     1, 0, 's'},
    {"ttl",           1, 0, 't'},
    #ifdef FAKE_SUPPORT
    {"fake-tls",      1, 0, 'l'},
    {"fake-http",     1, 0, 'o'},
    {"tls-sni",       1, 0, 'n'},
    #endif
    {"mod-http",      1, 0, 'M'},
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


void daemonize(void)
{
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        exit(1);
    }
    else if (pid) {
        exit(0);
    }
    if (setsid() < 0) {
        exit(1);
    }
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    open("/dev/null", O_RDWR);
    dup(0);
    dup(0);
}


int get_addr(char *str, struct sockaddr_ina *addr)
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
        perror("socket");
        return -1;
    }
    if (getsockopt(fd, IPPROTO_IP, IP_TTL,
             (char *)&orig_ttl, &tsize) < 0) {
        perror("getsockopt IP_TTL");
    }
    close(fd);
    return orig_ttl;
}


int main(int argc, char **argv) 
{
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
    
    char daemon = 0;
    char *pidfile = 0;
    
    int rez;
    int invalid = 0;
    
    long val = 0;
    char *end = 0;
    uint16_t port = htons(1080);
    
    while (!invalid && (rez = getopt_long_only(
             argc, argv, opt, options, 0)) != -1) {
        switch (rez) {
        
        case 'D':
            daemon = 1;
            break;
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
        case 'f':
            pidfile = optarg;
            break;
        
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
            
        case 'H':
            params.split_host = 1;
            break;
            
        case 'm':
            if (params.attack != DESYNC_NONE) {
                fprintf(stderr, "methods incompatible\n");
                invalid = 1;
            }
            else switch (*optarg) {
                case 's': 
                    params.attack = DESYNC_SPLIT;
                    break;
                case 'd': 
                    params.attack = DESYNC_DISORDER;
                    break;
                #ifdef FAKE_SUPPORT
                case 'f': 
                    params.attack = DESYNC_FAKE;
                    break;
                #endif
                default:
                    invalid = 1;
            }
            break;
        
        case 's':    
            val = strtol(optarg, &end, 0);
            if (val < INT_MIN || val > INT_MAX || *end)
                invalid = 1;
            else
                params.split = val;
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
                perror("read file");
                return -1;
            }
            break;
            
        case 'o':
            fake_http.data = ftob(optarg, &fake_http.size);
            if (!fake_http.data) {
                perror("read file");
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
            params.sfdelay = strtoul(optarg, &end, 0);
            if (optarg == end || params.sfdelay > 1000000 || *end)
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

    FILE *file;
    if (pidfile) {
        file = fopen(pidfile, "w");
        if (!file) {
            perror("fopen");
            return -1;
        }
    }
    if (daemon) {
        daemonize();
    }
    if (pidfile) {
        fprintf(file, "%d", getpid());
        fclose(file);
    }
    
    if (!params.def_ttl && params.attack != DESYNC_NONE) {
        if ((params.def_ttl = get_default_ttl()) < 1) {
            return -1;
        }
    }
    
    return listener(s);
}
