#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#include <params.h>
#include <proxy.h>
#include <packets.h>

#define VERSION 1

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
    .mod_http = 0,
    
    .ipv6 = 1,
    .resolve = 1,
    .de_known = 0,
    .max_open = 512,
    
    .bfsize = 16384,
    .send_bfsz = 65536,
    .debug = 0
};


char *ftob(char *name)
{
    char *buffer = 0;
    
    FILE *file = fopen(name, "rb");
    if (!file)
        return 0;
    do {
        if (fseek(file, 0, SEEK_END)) {
            break;
        }
        long size = ftell(file);
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


int main(int argc, char **argv) 
{
    struct sockaddr_ina s = {
        .in = {
            .sin_family = AF_INET,
            .sin_port = htons(1080)
    }};
    
    char daemon = 0;
    char *pidfile = 0;
    
    const char help_text[] = {
        //"Proxy:\n"
        "    -i, --ip, <ip>            Listening IP address\n"
        "    -p, --port <num>          Listening port num\n"
        "    -D, --daemon              Daemonize\n"
        "    -f, --pidfile <file>      Write pid to file\n"
        "    -c, --max-conn <count>    Connection count limit, default 512\n"
        "    -N, --no-domain           Deny domain resolving\n"
        "    -K, --desync-known        Desync only HTTP and TLS with SNI\n"
        //"Desync:\n"
        "    -m, --method <s|d|f>      Desync method: split,disorder,fake\n"
        "    -s, --split-pos <offset>  Split position, default 3\n"
        "    -H, --split-at-host       Add Host/SNI offset to split position\n"
        "    -t, --ttl <num>           TTL of fake packets, default 8\n"
        "    -l, --fake-tls <file>\n"
        "    -o, --fake-http <file>    Set custom fake packet\n"
        "    -n, --tls-sni <str>       Change SNI in fake CH\n"
        "    -M, --mod-http <h,d,r>    Modify http: hcsmix,dcsmix,rmspace\n"
    };
    
    const struct option options[] = {
        {"daemon",        0, 0, 'D'},
        {"no-domain",     0, 0, 'N'},
        {"no-ipv6",       0, 0, 'X'}, //
        {"desync-known ", 0, 0, 'K'},
        {"split-at-host", 0, 0, 'H'},
        {"help",          0, 0, 'h'},
        {"version",       0, 0, 'v'},
        {"pidfile",       1, 0, 'f'},
        {"ip",            1, 0, 'i'},
        {"port",          1, 0, 'p'},
        {"bfs",           1, 0, 'b'}, //
        {"snd-bfs",       1, 0, 'B'}, //
        {"max-conn",      1, 0, 'c'},
        {"method",        1, 0, 'm'},
        {"split-pos",     1, 0, 's'},
        {"ttl",           1, 0, 't'},
        {"fake-tls",      1, 0, 'l'},
        {"fake-http",     1, 0, 'o'},
        {"tls-sni",       1, 0, 'n'},
        {"mod-http",      1, 0, 'M'},
        {"global-ttl",    1, 0, 'g'}, //
        {"delay",         1, 0, 'w'}, //
        {"debug",         1, 0, 'x'}, //
        
        {0}
    };
    int rez;
    int invalid = 0;
    
    long val = 0;
    char *end = 0;
    
    while (!invalid && (rez = getopt_long_only(argc, argv,
             "DNXKHhvf:i:p:b:B:c:m:s:t:l:o:n:M:g:w:x:", options, 0)) != -1) {
        switch (rez) {
        
        case 'D':
            daemon = 1;
            break;
        case 'f':
            pidfile = optarg;
            break;
        case 'N':
            params.resolve = 0;
            break;
        case 'X':
            params.ipv6 = 0;
            break;
        case 'K':
            params.de_known = 1;
            break;
        case 'h':
            printf(help_text);
            return 0;
        case 'v':
            printf("%d\n", VERSION);
            return 0;
            
        case 'b': //
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > INT_MAX/4 || *end)
                invalid = 1;
            else
                params.bfsize = val;
            break;
            
        case 'B': //
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > INT_MAX || *end)
                invalid = 1;
            else
                params.send_bfsz = val;
            break;
            
        case 'i':
            if (strchr(optarg, ':'))
                s.in.sin_family = AF_INET6;
            else
                s.in.sin_family = AF_INET;
                
            if (!inet_pton(s.in.sin_family, optarg,
                    (s.in.sin_family == AF_INET ? 
                    (char *)&s.in.sin_addr : (char *)&s.in6.sin6_addr)))
                invalid = 1;
            break;
            
        case 'p':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 0xffff || *end)
                invalid = 1;
            else
                s.in.sin_port = htons(val);
            break;
            
        case 'c':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val >= (0xffff/2) || *end) 
                invalid = 1;
            else
                params.max_open = val;
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
                case 'f': 
                    params.attack = DESYNC_FAKE;
                    break;
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
            
        case 'H':
            params.split_host = 1;
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
            fake_tls.data = ftob(optarg);
            if (!fake_tls.data) {
                perror("read file");
                return -1;
            }
            break;
            
        case 'o':
            fake_http.data = ftob(optarg);
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
            
        case 'g': //
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 255 || *end)
                invalid = 1;
            else
                params.def_ttl = val;
            break;
            
        case 'w': //
            params.sfdelay = strtoul(optarg, &end, 0);
            if (optarg == end || params.sfdelay > 1000000 || *end)
                invalid = 1;
            break;
            
        case 'x': //
            params.debug = strtol(optarg, 0, 0);
            if (params.debug < 0)
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
    if (params.send_bfsz * 2 <= params.bfsize) {
        fprintf(stderr, "send buffer too small\n");
        return -1;
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
    
    if (!params.def_ttl) {
        int orig_ttl, fd;
        socklen_t tsize = sizeof(orig_ttl);
        if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
            perror("socket");  
            return -1;  
        }
        if (getsockopt(fd, IPPROTO_IP, IP_TTL,
                 (char *)&orig_ttl, &tsize) < 0) {
            perror("getsockopt IP_TTL");
            close(fd);
            return -1;
        }
        close(fd);
        params.def_ttl = orig_ttl;
    }
    return listener(s);
}