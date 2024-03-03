#include <stdio.h>
#include <string.h>

#ifndef _WIN32
    #include <unistd.h>
    #include <time.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/tcp.h>
    #include <sys/mman.h>
    
    #ifdef __linux__
        #include <sys/sendfile.h>
        #define _sendfile(outfd, infd, start, len) sendfile(outfd, infd, start, len)
    #else
        #include <sys/uio.h>
        #define _sendfile(outfd, infd, start, len) sendfile(infd, outfd, start, len, 0, 0)
    #endif

    #ifdef MFD_CLOEXEC
        #include <sys/syscall.h>
        #define memfd_create(name, flags) syscall(__NR_memfd_create, name, flags);
    #else
        #define memfd_create(name, flags) fileno(tmpfile())
    #endif
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
#endif

#include <params.h>
#include <packets.h>
#include <error.h>


static inline int get_family(struct sockaddr *dst)
{
    if (dst->sa_family == AF_INET6) {
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dst;
        static char *pat = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
        
        if (!memcmp(&d6->sin6_addr, pat, 12)) {
            return AF_INET;
        }
    }
    return dst->sa_family;
}


int setttl(int fd, int ttl, int family) {
    int _ttl = ttl;
    
    if (family == AF_INET) {
        if (setsockopt(fd, IPPROTO_IP,
                 IP_TTL, (char *)&_ttl, sizeof(_ttl)) < 0) {
            uniperror("setsockopt IP_TTL");
            return -1;
        }
    }
    else if (setsockopt(fd, IPPROTO_IPV6,
             IPV6_UNICAST_HOPS, (char *)&_ttl, sizeof(_ttl)) < 0) {
        uniperror("setsockopt IPV6_UNICAST_HOPS");
        return -1;
    }
    return 0;
}

#ifndef _WIN32
static inline void delay(long mk)
{
    struct timespec time = { 
         .tv_nsec = mk * 1000
    };
    nanosleep(&time, 0);
}
#else
#define delay(mk) {}
#endif

#ifndef _WIN32
int fake_attack(int sfd, char *buffer,
        size_t n, int cnt, int pos, int fa)
{
    struct packet pkt = cnt != IS_HTTP ? fake_tls : fake_http;
    size_t psz = pkt.size;
    
    int ffd = memfd_create("name", O_RDWR);
    if (ffd < 0) {
        uniperror("memfd_create");
        return -1;
    }
    char *p = 0;
    int status = -1;
    
    while (status) {
        if (ftruncate(ffd, pos) < 0) {
            uniperror("ftruncate");
            break;
        }
        p = mmap(0, pos, PROT_WRITE, MAP_SHARED, ffd, 0);
        if (p == MAP_FAILED) {
            uniperror("mmap");
            p = 0;
            break;
        }
        memcpy(p, pkt.data, psz < pos ? psz : pos);
        
        if (setttl(sfd, params.ttl, fa) < 0) {
            break;
        }
        if (_sendfile(sfd, ffd, 0, pos) < 0) {
            uniperror("sendfile");
            break;
        }
        struct timespec delay = { 
            .tv_nsec = params.sfdelay * 1000
        };
        nanosleep(&delay, 0);
        memcpy(p, buffer, pos);
        
        if (setttl(sfd, params.def_ttl, fa) < 0) {
            break;
        }
        if (send(sfd, buffer + pos, n - pos, 0) < 0) {
            uniperror("send");
            break;
        }
        status = 0;
    }
    if (p) munmap(p, pos);
    close(ffd);
    return status;
}
#endif

int disorder_attack(int sfd, char *buffer,
        ssize_t n, int pos, int fa)
{
    int bttl = 1;
    if (setttl(sfd, bttl, fa) < 0) {
        return -1;
    }
    if (send(sfd, buffer, pos, 0) < 0) {
        uniperror("send");
        return -1;
    }
    if (setttl(sfd, params.def_ttl, fa) < 0) {
        return -1;
    }
    if (send(sfd, buffer + pos, n - pos, 0) < 0) {
        uniperror("send");
        return -1;
    }
    return 0;
}


int oob_attack(int sfd, char *buffer,
        ssize_t n, int pos, int fa)
{
    int size = oob_data.size - 1;
    char *data = oob_data.data + 1;
    
    char rchar = buffer[pos];
    buffer[pos] = data[0];
    
    if (send(sfd, buffer, pos + 1, MSG_OOB) < 0) {
        uniperror("send");
        buffer[pos] = rchar;
        return -1;
    }
    buffer[pos] = rchar;
    if (size) {
        delay(params.sfdelay);
    }
    for (int i = 0; i < size; i++) {
        if (send(sfd, data + i, 1, MSG_OOB) < 0) {
            uniperror("send");
            return -1;
        }
        if (size != 1) {
            delay(params.sfdelay);
        }
    }
    if (send(sfd, buffer + pos, n - pos, 0) < 0) {
        uniperror("send");
        return -1;
    }
    return 0;
}

            
int desync(int sfd, char *buffer, size_t bfsize,
        ssize_t n, struct sockaddr *dst)
{
    int pos = params.split;
    char *host = 0;
    int len = 0, type = 0;
    int fa = get_family(dst);
    
    if ((len = parse_tls(buffer, n, &host))) {
        type = IS_HTTPS;
    }
    else if ((len = parse_http(buffer, n, &host, 0))) {
        type = IS_HTTP;
    }
    if (len && host) {
        LOG(LOG_S, "host: %.*s\n", len, host);
    }
    
    if (type == IS_HTTP && params.mod_http) {
        LOG(LOG_S, "modify HTTP: n=%ld\n", n);
        if (mod_http(buffer, n, params.mod_http)) {
            LOG(LOG_E, "mod http error\n");
            return -1;
        }
    }
    else if (type == IS_HTTPS && params.tlsrec) {
        int o = params.tlsrec_pos;
        if (params.tlsrec_sni) {
            o += (host - buffer - 5);
        }
        else if (o < 0) {
            o += n;
        }
        LOG(LOG_S, "tlsrec: pos=%d, n=%ld\n", o, n);
        n = part_tls(buffer, bfsize, n, o);
    }
    
    if (params.split_host) {
        if (host)
            pos += (host - buffer);
        else
            pos = 0;
    }
    else if (pos < 0) {
        pos += n;
    }
    LOG(LOG_L, "split-pos=%d, n=%ld\n", pos, n);
    
    if (params.custom_ttl) {
        if (setttl(sfd, params.def_ttl, fa) < 0) {
            return -1;
        }
    }
    if (pos <= 0 || pos >= n ||
            params.attack == DESYNC_NONE ||
            (!type && params.de_known))
    {
        if (send(sfd, buffer, n, 0) < 0) {
            uniperror("send");
            return -1;
        }
    }
    else switch (params.attack) {
        #ifndef _WIN32
        case DESYNC_FAKE:
            return fake_attack(sfd, buffer, n, type, pos, fa);
        #endif
        case DESYNC_DISORDER:
            return disorder_attack(sfd, buffer, n, pos, fa);
        
        case DESYNC_OOB:
            return oob_attack(sfd, buffer, n, pos, fa);
            
        case DESYNC_SPLIT:
        default:
            if (send(sfd, buffer, pos, 0) < 0) {
                uniperror("send");
                return -1;
            }
            if (send(sfd, buffer + pos, n - pos, 0) < 0) {
                uniperror("send");
                return -1;
            }
    }
    return 0;
}
