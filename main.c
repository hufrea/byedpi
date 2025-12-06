#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <limits.h>
#include <ctype.h>

#include "params.h"
#include "proxy.h"
#include "packets.h"
#include "error.h"
#include "conev.h"

#ifndef _WIN32
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <fcntl.h>
    #include <netinet/in.h>
    #include <netinet/tcp.h>
    #include <sys/socket.h>
    
    #define DAEMON
#else
    #include <ws2tcpip.h>
    #include "win_service.h"
    #define close(fd) closesocket(fd)
#endif

#define VERSION "17.3"

ASSERT(sizeof(struct in_addr) == 4)
ASSERT(sizeof(struct in6_addr) == 16)


struct packet fake_tls = { 
    sizeof(tls_data), tls_data, 0,
},
fake_http = { 
    sizeof(http_data), http_data, 0,
},
fake_udp = { 
    sizeof(udp_data), udp_data, 0,
};


struct params params = {
    .await_int = 10,
    
    .ipv6 = 1,
    .resolve = 1,
    .udp = 1,
    .max_open = 512,
    .bfsize = 16384,
    .baddr = {
        .in6 = { .sin6_family = AF_INET6 }
    },
    .laddr = {
        .in = { .sin_family = AF_INET }
    },
    .debug = 0
};


static const char help_text[] = {
    "    -i, --ip, <ip>            Listening IP, default 0.0.0.0\n"
    "    -p, --port <num>          Listening port, default 1080\n"
    #ifdef DAEMON
    "    -D, --daemon              Daemonize\n"
    "    -w, --pidfile <filename>  Write PID to file\n"
    #endif
    #ifdef __linux__
    "    -E, --transparent         Transparent proxy mode\n"
    #endif
    "    -c, --max-conn <count>    Connection count limit, default 512\n"
    "    -N, --no-domain           Deny domain resolving\n"
    "    -U, --no-udp              Deny UDP association\n"
    "    -I  --conn-ip <ip>        Connection binded IP, default ::\n"
    "    -b, --buf-size <size>     Buffer size, default 16384\n"
    "    -x, --debug <level>       Print logs, 0, 1 or 2\n"
    "    -g, --def-ttl <num>       TTL for all outgoing connections\n"
    // desync options
    #ifdef TCP_FASTOPEN_CONNECT
    "    -F, --tfo                 Enable TCP Fast Open\n"
    #endif
    "    -A, --auto <t,r,s,n>      Try desync params after this option\n"
    "                              Detect: torst,redirect,ssl_err,none\n"
    "    -L, --auto-mode <0-3>     Mode: 1 - post_resp, 2 - sort, 3 - 1+2\n"
    "    -u, --cache-ttl <sec>     Lifetime of cached desync params for IP\n"
    "    -y, --cache-dump <file|-> Dump cache to file or stdout\n"
    #ifdef TIMEOUT_SUPPORT
    "    -T, --timeout <sec>       Timeout waiting for response, after which trigger auto\n"
    #endif
    "    -K, --proto <t,h,u,i>     Protocol whitelist: tls,http,udp,ipv4\n"
    "    -H, --hosts <file|:str>   Hosts whitelist, filename or :string\n"
    "    -j, --ipset <file|:str>   IP whitelist\n"
    "    -V, --pf <port[-portr]>   Ports range whitelist\n"
    "    -R, --round <num[-numr]>  Number of request to which desync will be applied\n"
    "    -s, --split <pos_t>       Position format: offset[:repeats:skip][+flag1[flag2]]\n"
    "                              Flags: +s - SNI offset, +h - HTTP host offset, +n - null\n"
    "                              Additional flags: +e - end, +m - middle\n"
    "    -d, --disorder <pos_t>    Split and send reverse order\n"
    "    -o, --oob <pos_t>         Split and send as OOB data\n"
    "    -q, --disoob <pos_t>      Split and send reverse order as OOB data\n"
    #ifdef FAKE_SUPPORT
    "    -f, --fake <pos_t>        Split and send fake packet\n"
    #ifdef __linux__
    "    -S, --md5sig              Add MD5 Signature option for fake packets\n"
    #endif
    "    -n, --fake-sni <str>      Change SNI in fake\n"
    "                              Replaced: ? - rand let, # - rand num, * - rand let/num\n"
    #endif
    "    -t, --ttl <num>           TTL of fake packets, default 8\n"
    "    -O, --fake-offset <pos_t> Fake data start offset\n"
    "    -l, --fake-data <f|:str>  Set custom fake packet\n"
    "    -Q, --fake-tls-mod <flag> Modify fake TLS CH: rand,orig,msize=<int>\n"
    "    -e, --oob-data <char>     Set custom OOB data\n"
    "    -M, --mod-http <h,d,r>    Modify HTTP: hcsmix,dcsmix,rmspace\n"
    "    -r, --tlsrec <pos_t>      Make TLS record at position\n"
    "    -m, --tlsminor <ver>      Change minor version of TLS\n"
    "    -a, --udp-fake <count>    UDP fakes count, default 0\n"
    #ifdef __linux__
    "    -Y, --drop-sack           Drop packets with SACK extension\n"
    #endif
};


const struct option options[] = {
    #ifdef DAEMON
    {"daemon",        0, 0, 'D'},
    {"pidfile",       1, 0, 'w'},
    #endif
    {"no-domain",     0, 0, 'N'},
    {"no-ipv6",       0, 0, 'X'},
    {"no-udp",        0, 0, 'U'},
    {"http-connect",  0, 0, 'G'},
    {"help",          0, 0, 'h'},
    {"version",       0, 0, 'v'},
    {"ip",            1, 0, 'i'},
    {"port",          1, 0, 'p'},
    #ifdef __linux__
    {"transparent",   0, 0, 'E'},
    #endif
    {"conn-ip",       1, 0, 'I'},
    {"buf-size",      1, 0, 'b'},
    {"max-conn",      1, 0, 'c'},
    {"debug",         1, 0, 'x'},
    
    #ifdef TCP_FASTOPEN_CONNECT
    {"tfo",           0, 0, 'F'},
    #endif
    {"auto",          1, 0, 'A'},
    {"auto-mode",     1, 0, 'L'},
    {"cache-ttl",     1, 0, 'u'},
    #ifdef TIMEOUT_SUPPORT
    {"timeout",       1, 0, 'T'},
    #endif
    {"copy",          1, 0, 'B'},
    {"cache-dump",    1, 0, 'y'},
    {"proto",         1, 0, 'K'},
    {"hosts",         1, 0, 'H'},
    {"pf",            1, 0, 'V'},
    {"round",         1, 0, 'R'},
    {"split",         1, 0, 's'},
    {"disorder",      1, 0, 'd'},
    {"oob",           1, 0, 'o'},
    {"disoob",        1, 0, 'q'},
    #ifdef FAKE_SUPPORT
    {"fake",          1, 0, 'f'},
    #ifdef __linux__
    {"md5sig",        0, 0, 'S'},
    #endif
    {"fake-sni",      1, 0, 'n'},
    #endif
    {"ttl",           1, 0, 't'},
    {"fake-data",     1, 0, 'l'},
    {"fake-offset",   1, 0, 'O'},
    {"fake-tls-mod",  1, 0, 'Q'},
    {"oob-data",      1, 0, 'e'},
    {"mod-http",      1, 0, 'M'},
    {"tlsrec",        1, 0, 'r'},
    {"tlsminor",      1, 0, 'm'},
    {"udp-fake",      1, 0, 'a'},
    {"def-ttl",       1, 0, 'g'},
    {"wait-send",     0, 0, 'Z'}, //
    {"await-int",     1, 0, 'W'}, //
    #ifdef __linux__
    {"drop-sack",     0, 0, 'Y'},
    {"protect-path",  1, 0, 'P'}, //
    #endif
    {"ipset",         1, 0, 'j'},
    {"to-socks5",     1, 0, 'C'}, //
    {"comment",       1, 0, '#'}, //
    {0}
};
    

ssize_t parse_cform(char *buffer, size_t blen, 
        const char *str, size_t slen)
{
    static char esca[] = {
        'r','\r','n','\n','t','\t','\\','\\',
        'f','\f','b','\b','v','\v','a','\a', 0
    };
    size_t i = 0, p = 0;
    for (; p < slen && i < blen; ++p, ++i) {
        if (str[p] != '\\') {
            buffer[i] = str[p];
            continue;
        }
        p++;
        char *e = esca;
        for (; *e; e += 2) {
            if (*e == str[p]) {
                buffer[i] = *(e + 1);
                break;
            }
        }
        if (*e) {
            continue;
        }
        int n = 0;
        if (sscanf(&str[p], "x%2hhx%n", (uint8_t *)&buffer[i], &n) == 1
              || sscanf(&str[p], "%3hho%n", (uint8_t *)&buffer[i], &n) == 1) {
            p += (n - 1);
            continue;
        }
        i--; p--;
    }
    return i;
}


char *data_from_str(const char *str, ssize_t *size)
{
    ssize_t len = strlen(str);
    if (len == 0) {
        return 0;
    }
    char *d = malloc(len);
    if (!d) {
        return 0;
    }
    ssize_t i = parse_cform(d, len, str, len);
    
    char *m = len != i ? realloc(d, i) : 0;
    if (i == 0) {
        return 0;
    }
    *size = i;
    return m ? m : d;
}


char *ftob(const char *str, ssize_t *sl)
{
    if (*str == ':') {
        return data_from_str(str + 1, sl);
    }
    char *buffer = 0;
    long size;
    
    FILE *file = fopen(str, "rb");
    if (!file) {
        return 0;
    }
    do {
        if (fseek(file, 0, SEEK_END)) {
            break;
        }
        size = ftell(file);
        if (size <= 0) {
            break;
        }
        if (fseek(file, 0, SEEK_SET)) {
            break;
        }
        if (!(buffer = malloc(size))) {
            break;
        }
        size_t rs = fread(buffer, 1, size, file);
        if (rs != (size_t )size) {
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


static inline int lower_char(char *cl)
{
    char c = *cl;
    if (c < 'A') {
        if (c > '9' || c < '-')
            return -1;
    }
    else if (c < 'a') {
        if (c > 'Z') 
            return -1;
        *cl = c + 32;
    }
    else if (c > 'z') 
        return -1;
    return 0;
}


struct mphdr *parse_hosts(char *buffer, size_t size)
{
    struct mphdr *hdr = mem_pool(MF_STATIC, CMP_HOST);
    if (!hdr) {
        return 0;
    }
    size_t num = 0;
    bool drop = 0;
    char *end = buffer + size;
    char *e = buffer, *s = buffer;
    
    for (; e <= end; e++) {
        if (e != end && *e != ' ' && *e != '\n' && *e != '\r') {
            if (lower_char(e)) {
                drop = 1;
            }
            continue;
        }
        if (s == e) {
            s++;
            continue;
        }
        if (!drop) {
            if (!mem_add(hdr, s, e - s, sizeof(struct elem))) {
                mem_destroy(hdr);
                return 0;
            }
        } 
        else {
            LOG(LOG_E, "invalid host: num: %zd \"%.*s\"\n", num + 1, ((int )(e - s)), s);
            drop = 0;
        }
        num++;
        s = e + 1;
    }
    LOG(LOG_S, "hosts count: %zd\n", hdr->count);
    return hdr;
}


static int parse_ip(char *out, char *str, size_t size)
{
    long bits = 0;
    char *sep = memchr(str, '/', size);
    if (sep) {
        bits = strtol(sep + 1, 0, 10);
        if (bits <= 0) {
            return 0;
        }
        *sep = 0;
    }
    int len = sizeof(struct in_addr);
    
    if (inet_pton(AF_INET, str, out) <= 0) {
        if (inet_pton(AF_INET6, str, out) <= 0) {
            return 0;
        }
        else len = sizeof(struct in6_addr);
    }
    if (!bits || bits > len * 8) bits = len * 8;
    return (int )bits;
}


struct mphdr *parse_ipset(char *buffer, size_t size)
{
    struct mphdr *hdr = mem_pool(0, CMP_BITS);
    if (!hdr) {
        return 0;
    }
    size_t num = 0;
    char *end = buffer + size;
    char *e = buffer, *s = buffer;
    
    for (; e <= end; e++) {
        if (e != end && *e != ' ' && *e != '\n' && *e != '\r') {
            continue;
        }
        if (s == e) {
            s++;
            continue;
        }
        char ip[e - s + 1];
        ip[e - s] = 0;
        memcpy(ip, s, e - s);
        
        num++;
        s = e + 1;
        
        char ip_stack[sizeof(struct in6_addr)];
        int bits = parse_ip(ip_stack, ip, sizeof(ip));
        if (bits <= 0) {
            LOG(LOG_E, "invalid ip: num: %zd\n", num);
            continue;
        }
        int len = bits / 8 + (bits % 8 ? 1 : 0);
        char *ip_raw = malloc(len);
        memcpy(ip_raw, ip_stack, len);
        
        struct elem *elem = mem_add(hdr, ip_raw, bits, sizeof(struct elem));
        if (!elem) {
            free(ip_raw);
            mem_destroy(hdr);
            return 0;
        }
    }
    LOG(LOG_S, "ip count: %zd\n", hdr->count);
    return hdr;
}


int get_addr(const char *str, union sockaddr_u *addr)
{
    uint16_t port = 0;
    const char *s = str, *e = 0;
    const char *end = 0, *p = str;
    
    if (*str == '[') {
        e = strchr(str, ']');
        if (!e) return -1;
        s++; p = e + 1;
    }
    p = strchr(p, ':');
    if (p && isdigit(p[1])) {
        long val = strtol(p + 1, (char **)&end, 0);
        if (val <= 0 || val > 0xffff || *end)
            return -1;
        else
            port = htons(val);
        if (!e) e = p;
    }
    if (!e) {
        e = strchr(str, 0);
    }
    char str_ip[(e - s) + 1];
    memcpy(str_ip, s, e - s);
    str_ip[e - s] = 0;
    
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_NUMERICHOST;
    
    if (getaddrinfo(str_ip, 0, &hints, &res) || !res) {
        return -1;
    }
    
    if (res->ai_addr->sa_family == AF_INET6)
        addr->in6.sin6_addr = (
            (struct sockaddr_in6 *)res->ai_addr)->sin6_addr;
    else
        addr->in.sin_addr = (
            (struct sockaddr_in *)res->ai_addr)->sin_addr;
            
    addr->sa.sa_family = res->ai_addr->sa_family;
    if (port) {
        addr->in6.sin6_port = port;
    }
    freeaddrinfo(res);
    return 0;
}


int get_default_ttl(void)
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


bool ipv6_support(void)
{
    int fd = socket(AF_INET6, SOCK_STREAM, 0);
    if (fd < 0) {
        return 0;
    }
    close(fd);
    return 1;
}


int parse_offset(struct part *part, const char *str)
{
    char *end = 0;
    long val = strtol(str, &end, 0);
    
    while (*end == ':') {
        long rs = strtol(end + 1, &end, 0);
        if (rs < 0 || rs > INT_MAX) {
            return -1;
        }
        if (!part->r) {
            if (!rs) 
                return -1;
            part->r = rs;
        }
        else {
            part->s = rs;
            break;
        }
    }
    if (*end == '+') {
        switch (*(end + 1)) {
            case 's':
                part->flag = OFFSET_SNI;
                break;
            case 'h': 
                part->flag = OFFSET_HOST;
                break;
            case 'n':
                break;
            default:
                return -1;
        }
        switch (*(end + 2)) {
            case 'e':
                part->flag |= OFFSET_END;
                break;
            case 'm':
                part->flag |= OFFSET_MID;
                break;
            case 'r': //
                part->flag |= OFFSET_RAND;
                break;
            case 's': //
                part->flag |= OFFSET_START;
        }
    }
    part->pos = val;
    return 0;
}


void *add(void **root, int *n, size_t ss)
{
    char *p = realloc(*root, ss * (*n + 1));
    if (!p) {
        uniperror("realloc");
        return 0;
    }
    *root = p;
    p = (p + ((*n) * ss));
    memset(p, 0, ss);
    *n = *n + 1;
    return p;
}


static struct desync_params *add_group(struct desync_params *prev)
{
    struct desync_params *dp = calloc(1, sizeof(*prev));
    if (!dp) {
        return 0;
    }
    if (prev) {
        dp->prev = prev;
        prev->next = dp;
    }
    dp->id = params.dp_n;
    dp->bit = 1 << dp->id;
    dp->str = "";
    
    params.dp_n++;
    return dp;
}


#ifdef DAEMON
int init_pid_file(const char *fname)
{
    params.pid_fd = open(fname, O_RDWR | O_CREAT, 0640);
    if (params.pid_fd < 0) {
        return -1;
    }
    struct flock fl = { 
        .l_whence = SEEK_CUR,
        .l_type = F_WRLCK
    };
    if (fcntl(params.pid_fd, F_SETLK, &fl) < 0) {
        return -1;
    }
    params.pid_file = fname;
    char pid_str[21];
    snprintf(pid_str, sizeof(pid_str), "%d", getpid());
    
    write(params.pid_fd, pid_str, strlen(pid_str));
    return 0;
}
#endif


void clear_params(void)
{
    #ifdef _WIN32
    WSACleanup();
    #endif
    #ifdef DAEMON
    if (params.pid_fd > 0) {
        close(params.pid_fd);
    }
    if (params.pid_file) {
        unlink(params.pid_file);
    }
    #endif
    if (params.mempool) {
        mem_destroy(params.mempool);
        params.mempool = 0;
    }
    struct desync_params *dp = params.dp;
    while (dp) {
        free(dp->parts);
        free(dp->tlsrec);
        free(dp->fake_data.data);
        free(dp->file_ptr);
        free(dp->fake_sni_list);
        mem_destroy(dp->hosts);
        mem_destroy(dp->ipset);
        
        struct desync_params *t = dp;
        dp = dp->next;
        memset(t, 0, sizeof(*t));
        free(t);
    }
    params.dp = 0;
}


int main(int argc, char **argv) 
{
    #ifdef _WIN32
    WSADATA wsa;
    
    if (WSAStartup(MAKEWORD(2, 2), &wsa)) {
        uniperror("WSAStartup");
        return -1;
    }
    if (register_winsvc(argc, argv)) {
        return 0;
    }
    #endif
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
    //
    params.laddr.in.sin_port = htons(1080);
    if (!ipv6_support()) {
        params.baddr.sa.sa_family = AF_INET;
    }
    
    const char *pid_file = 0;
    bool daemonize = 0;
    const char *cache_file = 0;
    
    int rez;
    int invalid = 0;
    
    long val = 0;
    char *end = 0;
    bool all_limited = 1;
    
    int curr_optind = 1;
    
    struct desync_params *dp = add_group(0);
    if (!dp) {
        clear_params();
        return -1;
    }
    params.dp = dp;
    
    while (!invalid && (rez = getopt_long(
             argc, argv, opt, options, 0)) != -1) {
        switch (rez) {
        
        case 'N':
            params.resolve = 0;
            break;
        case 'X':
            params.ipv6 = 0;
            break;
        case 'U':
            params.udp = 0;
            break;
        case 'G':
            params.http_connect = 1;
            break;
        #ifdef __linux__
        case 'E':
            params.transparent = 1;
            break;
        #endif
        
        #ifdef DAEMON
        case 'D':
            daemonize = 1;
            break;
            
        case 'w':
            pid_file = optarg;
            break;
        #endif
        case 'h':
            printf(help_text);
            clear_params();
            return 0;
        case 'v':
            printf("%s\n", VERSION);
            clear_params();
            return 0;
        
        case 'i':
            if (get_addr(optarg, &params.laddr) < 0)
                invalid = 1;
            break;
            
        case 'p':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 0xffff || *end)
                invalid = 1;
            else
                params.laddr.in.sin_port = htons(val);
            break;
            
        case 'I':
            if (get_addr(optarg, &params.baddr) < 0)
                invalid = 1;
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
            
        case 'y': //
            params.cache_file = optarg;
            break;
            
        // desync options
        
        case 'F':
            params.tfo = 1;
            break;
            
        case 'L':
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case '0': 
                        break;
                    case '1':
                    case 'p': 
                        params.auto_level |= AUTO_POST;
                        break;
                    case '2':
                    case 's': 
                        params.auto_level |= AUTO_SORT;
                        break;
                    case 'r':
                        params.auto_level = 0;
                        break;
                    case '3':
                        params.auto_level |= (AUTO_POST | AUTO_SORT);
                        break;
                    default:
                        invalid = 1;
                        continue;
                }
                end = strchr(end, ',');
                if (end) end++;
            }
            break;
            
        case 'A':
            if (optind < curr_optind) {
                optind = curr_optind;
                continue;
            }
            if (!(dp->hosts || dp->proto || dp->pf[0] || dp->detect || dp->ipset)) {
                all_limited = 0;
            }
            dp = add_group(dp);
            if (!dp) {
                clear_params();
                return -1;
            }
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case 't': 
                        dp->detect |= DETECT_TORST;
                        break;
                    case 'r': 
                        dp->detect |= DETECT_HTTP_LOCAT;
                        break;
                    case 'a':
                    case 's': 
                        dp->detect |= DETECT_TLS_ERR;
                        break;
                    case 'n': 
                        break;
                    default:
                        invalid = 1;
                        continue;
                }
                end = strchr(end, ',');
                if (end) end++;
            }
            if (dp->detect) {
                params.auto_level |= AUTO_RECONN;
            }
            dp->_optind = optind;
            break;
            
        case 'B':
            if (optind < curr_optind) {
                continue;
            }
            if (*optarg == 'i') {
                dp->pf[0] = htons(1);
                continue;
            }
            val = strtol(optarg, &end, 0);
            struct desync_params *itdp = params.dp;
            
            while (itdp && itdp->id != val - 1) {
                itdp = itdp->next;
            }
            if (!itdp) 
                invalid = 1;
            else {
                curr_optind = optind;
                optind = itdp->_optind;
            }
            break;
        
        case '#':
            dp->str = optarg;
            break;
            
        case 'u':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || (unsigned long)val > UINT_MAX || *end) {
                invalid = 1;
                break;
            }
            unsigned int *ct = add((void *)&params.cache_ttl,
                    &params.cache_ttl_n, sizeof(unsigned int));
            if (!ct) {
                invalid = 1;
                continue;
            }
            *ct = (unsigned int )val;
            break;
        
        case 'T':;
            #ifdef __linux__
            float f = strtof(optarg, &end);
            val = (long)(f * 1000);
            #else
            val = strtol(optarg, &end, 0);
            #endif
            if (val <= 0 || (unsigned long)val > UINT_MAX || *end)
                invalid = 1;
            else
                params.timeout = val;
            break;
            
        case 'K':
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case 't': 
                        dp->proto |= IS_TCP | IS_HTTPS;
                        break;
                    case 'h': 
                        dp->proto |= IS_TCP | IS_HTTP;
                        break;
                    case 'u': 
                        dp->proto |= IS_UDP;
                        break;
                    case 'i': 
                        dp->proto |= IS_IPV4;
                        break;
                    default:
                        invalid = 1;
                        continue;
                }
                end = strchr(end, ',');
                if (end) end++;
            }
            break;
            
        case 'H':;
            if (dp->file_ptr) {
                continue;
            }
            dp->file_ptr = ftob(optarg, &dp->file_size);
            if (!dp->file_ptr) {
                uniperror("read/parse");
                invalid = 1;
                continue;
            }
            dp->hosts = parse_hosts(dp->file_ptr, dp->file_size);
            if (!dp->hosts) {
                uniperror("parse_hosts");
                clear_params();
                return -1;
            }
            break;
            
        case 'j':;
            if (dp->ipset) {
                continue;
            }
            ssize_t size;
            char *data = ftob(optarg, &size);
            if (!data) {
                uniperror("read/parse");
                invalid = 1;
                continue;
            }
            dp->ipset = parse_ipset(data, size);
            if (!dp->ipset) {
                uniperror("parse_ipset");
                invalid = 1;
            }
            free(data);
            break;
            
        case 's':
        case 'd':
        case 'o':
        case 'q':
        case 'f':
            ;
            struct part *part = add((void *)&dp->parts,
                &dp->parts_n, sizeof(struct part));
            if (!part) {
                clear_params();
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
                case 'q': part->m = DESYNC_DISOOB;
                    break;
                case 'f': part->m = DESYNC_FAKE;
            }
            break;
            
        case 't':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 255 || *end) 
                invalid = 1;
            else
                dp->ttl = val;
            break;
            
        case 'S':
            dp->md5sig = 1;
            break;
            
        case 'O':
            if (parse_offset(&dp->fake_offset, optarg)) {
                invalid = 1;
                break;
            } else dp->fake_offset.m = 1;
            break;
            
        case 'Q':
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case 'r': 
                        dp->fake_mod |= FM_RAND;
                        break;
                    case 'o': 
                        dp->fake_mod |= FM_ORIG;
                        break;
                    case 'm': 
                        if ((end = strchr(end, '='))) {
                            val = strtol(end + 1, &end, 0);
                            if (!(val > INT_MAX || (*end && *end != ','))) {
                                dp->fake_tls_size = val;
                                break;
                            }
                        }
                        __attribute__((fallthrough));
                    default:
                        invalid = 1;
                        continue;
                }
                end = strchr(end, ',');
                if (end) end++;
            }
            break;
            
        case 'n':;
            const char **p = add((void *)&dp->fake_sni_list,
                    &dp->fake_sni_count, sizeof(optarg));
            if (!p) {
                invalid = 1;
                continue;
            }
            *p = optarg;
            break;
            
        case 'l':
            if (dp->fake_data.data) {
                continue;
            }
            dp->fake_data.data = ftob(optarg, &dp->fake_data.size);
            if (!dp->fake_data.data) {
                uniperror("read/parse");
                invalid = 1;
            }
            break;
            
        case 'e':
            val = parse_cform(dp->oob_char, 1, optarg, strlen(optarg));
            if (val != 1) {
                invalid = 1;
            }
            else dp->oob_char[1] = 1;
            break;
            
        case 'M':
            end = optarg;
            while (end && !invalid) {
                switch (*end) {
                    case 'r': 
                        dp->mod_http |= MH_SPACE;
                        break;
                    case 'h': 
                        dp->mod_http |= MH_HMIX;
                        break;
                    case 'd': 
                        dp->mod_http |= MH_DMIX;
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
            part = add((void *)&dp->tlsrec,
                &dp->tlsrec_n, sizeof(struct part));
            if (!part) {
                clear_params();
                return -1;
            }
            if (parse_offset(part, optarg)
                   || part->pos > 0xffff) {
                invalid = 1;
                break;
            }
            break;
            
        case 'm':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > 255 || *end) 
                invalid = 1;
            else {
                dp->tlsminor = val;
                dp->tlsminor_set = 1;
            }
            break;
            
        case 'a':
            val = strtol(optarg, &end, 0);
            if (val < 0 || val > INT_MAX || *end)
                invalid = 1;
            else
                dp->udp_fake_count = val;
            break;
            
        case 'V':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > USHRT_MAX)
                invalid = 1;
            else {
                dp->pf[0] = htons(val);
                if (*end == '-') {
                    val = strtol(end + 1, &end, 0);
                    if (val <= 0 || val > USHRT_MAX)
                        invalid = 1;
                }
                if (*end)
                    invalid = 1;
                else
                    dp->pf[1] = htons(val);
            }
            break;
            
        case 'R':
            val = strtol(optarg, &end, 0);
            if (val <= 0 || val > INT_MAX)
                invalid = 1;
            else {
                dp->rounds[0] = val;
                if (*end == '-') {
                    val = strtol(end + 1, &end, 0);
                    if (val <= 0 || val > INT_MAX)
                        invalid = 1;
                }
                if (*end)
                    invalid = 1;
                else
                    dp->rounds[1] = val;
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
            
        case 'Y':
            dp->drop_sack = 1;
            break;
        
        case 'Z':
            params.wait_send = 1;
            break;
        
        case 'W':
            params.await_int = atoi(optarg);
            break;
            
        case 'C':
            if (get_addr(optarg, &dp->ext_socks) < 0 
                    || !dp->ext_socks.in6.sin6_port) 
                invalid = 1;
            break;
        
        #ifdef __linux__
        case 'P':
            params.protect_path = optarg;
            break;
        #endif
        case 0:
            break;
            
        case '?':
            clear_params();
            return -1;
            
        default: 
            printf("?: %c\n", rez);
            clear_params();
            return -1;
        }
    }
    if (invalid) {
        fprintf(stderr, "invalid value: -%c %s\n", rez, optarg);
        clear_params();
        return -1;
    }
    if (all_limited) {
        dp = add_group(dp);
        if (!dp) {
            clear_params();
            return -1;
        }
    }
    if ((size_t )params.dp_n > sizeof(dp->bit) * 8) {
        LOG(LOG_E, "too many groups!\n");
    }
    if (params.baddr.sa.sa_family != AF_INET6) {
        params.ipv6 = 0;
    }
    if (!params.def_ttl) {
        if ((params.def_ttl = get_default_ttl()) < 1) {
            clear_params();
            return -1;
        }
    }
    if (!params.cache_ttl) {
        unsigned int *ct = add((void *)&params.cache_ttl,
            &params.cache_ttl_n, sizeof(unsigned int));
        if (!ct) {
            clear_params();
            return -1;
        }
        *ct = 100800;
    }
    params.mempool = mem_pool(MF_EXTRA, CMP_BYTES);
    if (!params.mempool) {
        uniperror("mem_pool");
        clear_params();
        return -1;
    }
    srand((unsigned int)time(0));
    
    #ifdef DAEMON
    if (daemonize && daemon(0, 0) < 0) {
        clear_params();
        return -1;
    }
    if (pid_file && init_pid_file(pid_file) < 0) {
        clear_params();
        return -1;
    }
    #endif
    if (params.cache_file && strcmp(params.cache_file, "-")) {
        FILE *f = fopen(params.cache_file, "r");
        if (!f)
            perror("fopen");
        else {
            load_cache(params.mempool, f);
            fclose(f);
            LOG(LOG_S, "cache ip count: %zd\n", params.mempool->count);
        }
    }
    
    int status = run(&params.laddr);
    
    for (dp = params.dp; dp; dp = dp->next) {
        LOG(LOG_S, "group: %d (%s), triggered: %d, pri: %d\n", dp->id, dp->str, dp->fail_count, dp->pri);
    }
    if (params.cache_file) {
        FILE *f = 0;
        if (!strcmp(params.cache_file, "-"))
            f = stdout;
        else {
            f = fopen(params.cache_file, "w");
        }
        if (!f) {
            perror("fopen");
            clear_params();
            return -1;
        }
        dump_cache(params.mempool, f);
        fclose(f);
    }
    clear_params();
    return status;
}
