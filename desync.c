#include <stdio.h>
#include <string.h>
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

#include <params.h>
#include <packets.h>


int setttl(int fd, int ttl, int family) {
    int _ttl = ttl;
    if (family == AF_INET) {
        if (setsockopt(fd, IPPROTO_IP, IP_TTL,
                 &_ttl, sizeof(_ttl)) < 0) {
            perror("setsockopt IP_TTL");
            return -1;
        }
    }
    else if (setsockopt(fd, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
             &_ttl, sizeof(_ttl)) < 0) {
        perror("setsockopt IPV6_UNICAST_HOPS");
        return -1;
    }
    return 0;
}


int fake_attack(int sfd, char *buffer, ssize_t n, int cnt, int pos, int fa)
{
    struct packet pkt = cnt != IS_HTTP ? fake_tls : fake_http;
    size_t psz = pkt.size;
    
    int ffd = memfd_create("name", O_RDWR);
    if (ffd < 0) {
        perror("memfd_create");
        return -1;
    }
    char *p = 0;
    int status = -1;
    
    while (status) {
        if (ftruncate(ffd, pos) < 0) {
            perror("ftruncate");
            break;
        }
        p = mmap(0, pos, PROT_WRITE, MAP_SHARED, ffd, 0);
        if (p == MAP_FAILED) {
            perror("mmap");
            break;
        }
        memcpy(p, pkt.data, psz < pos ? psz : pos);
        
        if (setttl(sfd, params.ttl, fa) < 0) {
            break;
        }
        if (_sendfile(sfd, ffd, 0, pos) < 0) {
            perror("sendfile");
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
            perror("send");
            break;
        }
        status = 0;
    }
    if (p) munmap(p, pos);
    close(ffd);
    return status;
}


int disorder_attack(int sfd, char *buffer, ssize_t n, int pos, int fa)
{
    int bttl = 1;
    if (setttl(sfd, bttl, fa) < 0) {
        return -1;
    }
    if (send(sfd, buffer, pos, 0) < 0) {
        perror("send");
        return -1;
    }
    if (setttl(sfd, params.def_ttl, fa) < 0) {
        return -1;
    }
    if (send(sfd, buffer + pos, n - pos, 0) < 0) {
        perror("send");
        return -1;
    }
    return 0;
}


int desync(int sfd, char *buffer, 
        ssize_t n, struct sockaddr *dst)
{
    int pos = params.split;
    char *host = 0;
    int len = 0, type = 0;
    int fa = dst->sa_family;
    
    if ((len = parse_tls(buffer, n, &host))) {
        type = IS_HTTPS;
    }
    else if ((len = parse_http(buffer, n, &host, 0))) {
        type = IS_HTTP;
    }
    LOG(LOG_S, "host: %.*s\n", len, host);
    
    if (type == IS_HTTP && params.mod_http) {
        if (mod_http(buffer, n, params.mod_http)) {
            fprintf(stderr, "mod http error\n");
            return -1;
        }
    }
    if (host && params.split_host)
        pos += (host - buffer);
    else if (pos < 0)
        pos += n;
    
    LOG(LOG_L, "split pos: %d, n: %ld\n", pos, n);
    
    if (pos <= 0 || pos >= n ||
            params.attack == DESYNC_NONE ||
            (!type && params.de_known)) 
    {
        if (send(sfd, buffer, n, 0) < 0) {
            perror("send");
            return -1;
        }
    }
    else switch (params.attack) {
        case DESYNC_FAKE:
            return fake_attack(sfd, buffer, n, type, pos, fa);
            
        case DESYNC_DISORDER:
            printf("disorder attack\n");
            return disorder_attack(sfd, buffer, n, pos, fa);
        
        case DESYNC_SPLIT:
        default:
            if (send(sfd, buffer, pos, 0) < 0) {
                perror("send");
                return -1;
            }
            if (send(sfd, buffer + pos, n - pos, 0) < 0) {
                perror("send");
                return -1;
            }
    }
    return 0;
}


int desync_udp(int fd, char *buffer, 
        ssize_t n, struct sockaddr_in6 *dst)
{
    if (params.desync_udp & DESYNC_UDP_FAKE) {
        if (setttl(fd, params.ttl, AF_INET) < 0) {
            return -1;
        }
        if (setttl(fd, params.ttl, AF_INET6) < 0) {
            return -1;
        }
        if (sendto(fd, fake_udp.data, fake_udp.size,
                0, (struct sockaddr *)dst, sizeof(*dst)) < 0) {
            perror("sendto");
            return -1;
        }
        if (setttl(fd, params.def_ttl, AF_INET) < 0) {
            return -1;
        }
        if (setttl(fd, params.def_ttl, AF_INET6) < 0) {
            return -1;
        }
    }
    ssize_t ns = sendto(fd,
        buffer, n, 0, (struct sockaddr *)dst, sizeof(*dst));
    if (ns < 0) {
        perror("sendto");
        return -1;
    }
    return 0;
}