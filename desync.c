
#include "desync.h"

#include <stdio.h>
#include <string.h>

#ifndef _WIN32
    #include <unistd.h>
    #include <time.h>
    #include <sys/time.h>
    #include <sys/socket.h>
    #include <sys/mman.h>
    #include <arpa/inet.h>
    #include <fcntl.h>

    #ifndef __linux__
    #include <netinet/tcp.h>
    #else    
    #include <sys/sendfile.h>
    #include <linux/tcp.h>

    #include <sys/syscall.h>
    
    #ifdef __GLIBC__
    extern long syscall();
    #endif

    #define memfd_create(name, flags) syscall(__NR_memfd_create, name, flags)
    #endif
#else
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <mswsock.h>
#endif
#define STR_MODE

#include "params.h"
#include "packets.h"
#include "error.h"


int get_family(struct sockaddr *dst)
{
#ifndef __NetBSD__
    if (dst->sa_family == AF_INET6) {
        struct sockaddr_in6 *d6 = (struct sockaddr_in6 *)dst;
        static char *pat = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
        
        if (!memcmp(&d6->sin6_addr, pat, 12)) {
            return AF_INET;
        }
    }
#endif
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
static inline void delay(long ms)
{
    struct timespec time = { 
         .tv_nsec = ms * 1e6
    };
    nanosleep(&time, 0);
}
#else
#define delay(ms) Sleep(ms)
#endif

#ifdef __linux__
void wait_send(int sfd)
{
    for (int i = 0; params.wait_send && i < 500; i++) {
        struct tcpi tcpi = {};
        socklen_t ts = sizeof(tcpi);
        
        if (getsockopt(sfd, IPPROTO_TCP,
                TCP_INFO, (char *)&tcpi, &ts) < 0) {
            uniperror("getsockopt TCP_INFO");
            break;
        }
        if (tcpi.state != 1) {
            LOG(LOG_E, "state: %d\n", tcpi.state);
            return;
        }
        if (ts < sizeof(tcpi)) {
            LOG(LOG_E, "tcpi_notsent_bytes not provided\n");
            params.wait_send = 0;
            break;
        }
        if (tcpi.notsent_bytes == 0) {
            return;
        }
        LOG(LOG_S, "not sent after %d ms\n", i);
        delay(1);
    }
    delay(params.sfdelay);
}
#define wait_send_if_support(sfd) \
    if (params.wait_send) wait_send(sfd)
#else
#define wait_send(sfd) delay(params.sfdelay)
#define wait_send_if_support(sfd) // :(
#endif

#ifndef _WIN32
ssize_t send_fake(int sfd, char *buffer,
        int cnt, long pos, int fa, struct desync_params *opt)
{
    struct sockaddr_in6 addr = {};
    socklen_t addr_size = sizeof(addr);
#ifdef __linux__
    if (opt->md5sig) {
        if (getpeername(sfd, 
                (struct sockaddr *)&addr, &addr_size) < 0) {
            uniperror("getpeername");
            return -1;
        }
    }
#endif
    struct packet pkt;
    if (opt->fake_data.data) {
        pkt = opt->fake_data;
    }
    else {
        pkt = cnt != IS_HTTP ? fake_tls : fake_http;
    }
    size_t psz = pkt.size;
#ifdef __linux__
    int ffd = memfd_create("name", 0);
    if (ffd < 0) {
        uniperror("memfd_create");
        return -1;
    }
#else
    int ffd = shm_open("/name", O_RDWR | O_CREAT, 0);
    if (ffd < 0) {
        uniperror("shm_open");
        return -1;
    }
#endif
    char *p = 0;
    ssize_t len = -1;
    
    while (1) {
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
        
        if (setttl(sfd, opt->ttl ? opt->ttl : 8, fa) < 0) {
            break;
        }

#ifdef __linux__
        if (opt->md5sig) {
            struct tcp_md5sig md5 = {
                .tcpm_keylen = 5
            };
            memcpy(&md5.tcpm_addr, &addr, addr_size);
            
            if (setsockopt(sfd, IPPROTO_TCP,
                    TCP_MD5SIG, (char *)&md5, sizeof(md5)) < 0) {
                uniperror("setsockopt TCP_MD5SIG");
                break;
            }
        }
#endif
        if (opt->ip_options && fa == AF_INET
            && setsockopt(sfd, IPPROTO_IP, IP_OPTIONS,
                opt->ip_options, opt->ip_options_len) < 0) {
            uniperror("setsockopt IP_OPTIONS");
            break;
        }
#ifdef __linux__
        len = sendfile(sfd, ffd, 0, pos);
        if (len < 0) {
            uniperror("sendfile");
            break;
        }
#endif
        wait_send(sfd);
        memcpy(p, buffer, pos);
        
        if (setttl(sfd, params.def_ttl, fa) < 0) {
            break;
        }
        if (opt->ip_options && fa == AF_INET
            && setsockopt(sfd, IPPROTO_IP,
                IP_OPTIONS, opt->ip_options, 0) < 0) {
            uniperror("setsockopt IP_OPTIONS");
            break;
        }
#ifdef __linux__
        if (opt->md5sig) {
            struct tcp_md5sig md5 = {
                .tcpm_keylen = 0
            };
            memcpy(&md5.tcpm_addr, &addr, addr_size);
            
            if (setsockopt(sfd, IPPROTO_TCP,
                    TCP_MD5SIG, (char *)&md5, sizeof(md5)) < 0) {
                uniperror("setsockopt TCP_MD5SIG");
                break;
            }
        }
#endif
        break;
    }
    if (p) munmap(p, pos);
    close(ffd);
    return len;
}
#else
OVERLAPPED ov = {};

ssize_t send_fake(int sfd, char *buffer,
        int cnt, long pos, int fa, struct desync_params *opt)
{
    struct packet pkt;
    if (opt->fake_data.data) {
        pkt = opt->fake_data;
    }
    else {
        pkt = cnt != IS_HTTP ? fake_tls : fake_http;
    }
    size_t psz = pkt.size;
    
    char path[MAX_PATH], temp[MAX_PATH + 1];
    int ps = GetTempPath(sizeof(temp), temp);
    if (!ps) {
        uniperror("GetTempPath");
        return -1;
    }
    if (!GetTempFileName(temp, "t", 0, path)) {
        uniperror("GetTempFileName");
        return -1;
    }
    LOG(LOG_L, "temp file: %s\n", path);
    
    HANDLE hfile = CreateFileA(path, GENERIC_READ | GENERIC_WRITE, 
        FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, 
        FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hfile == INVALID_HANDLE_VALUE) {
        uniperror("CreateFileA");
        return -1;
    }
    ssize_t len = -1;
    
    while (1) {
        ov.hEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
        if (!ov.hEvent) {
            uniperror("CreateEvent");
             break;
        }
        if (!WriteFile(hfile, pkt.data, psz < pos ? psz : pos, 0, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (psz < pos) {
            if (SetFilePointer(hfile, pos, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
                uniperror("SetFilePointer");
                break;
            }
            if (!SetEndOfFile(hfile)) {
                uniperror("SetFileEnd");
                break;
            }
        }
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            uniperror("SetFilePointer");
            break;
        }
        if (setttl(sfd, opt->ttl ? opt->ttl : 8, fa) < 0) {
            break;
        }
        if (!TransmitFile(sfd, hfile, pos, pos, &ov, 
                NULL, TF_USE_KERNEL_APC | TF_WRITE_BEHIND)) {
            if ((GetLastError() != ERROR_IO_PENDING) 
                        && (WSAGetLastError() != WSA_IO_PENDING)) {
                uniperror("TransmitFile");
                break;
            }
        }
        wait_send(sfd);
        
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            uniperror("SetFilePointer");
            break;
        }
        if (!WriteFile(hfile, buffer, pos, 0, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (setttl(sfd, params.def_ttl, fa) < 0) {
            break;
        }
        len = pos;
        break;
    }
    if (!CloseHandle(hfile)
            || (ov.hEvent && !CloseHandle(ov.hEvent))) {
        uniperror("CloseHandle");
        return -1;
    }
    return len;
}
#endif

ssize_t send_oob(int sfd, char *buffer,
        ssize_t n, long pos)
{
    ssize_t size = oob_data.size - 1;
    char *data = oob_data.data + 1;
    
    char rchar = buffer[pos];
    buffer[pos] = oob_data.data[0];
    
    ssize_t len = send(sfd, buffer, pos + 1, MSG_OOB);
    buffer[pos] = rchar;
    
    if (len < 0) {
        uniperror("send");
        return -1;
    }
    len--;
    if (len != pos) {
        return len;
    }
    if (size) {
        wait_send(sfd);
    }
    for (long i = 0; i < size; i++) {
        if (send(sfd, data + i, 1, MSG_OOB) < 0) {
            uniperror("send");
            if (get_e() == EAGAIN) {
                return len;
            }
        }
        if (size != 1) {
            wait_send(sfd);
        }
    }
    return len;
}


ssize_t send_disorder(int sfd, 
        char *buffer, long pos, int fa)
{
    int bttl = 1;
    
    if (setttl(sfd, bttl, fa) < 0) {
        return -1;
    }
    ssize_t len = send(sfd, buffer, pos, 0);
    if (len < 0) {
        uniperror("send");
    }
    wait_send_if_support(sfd);
    
    if (setttl(sfd, params.def_ttl, fa) < 0) {
        return -1;
    }
    return len;
}


ssize_t desync(int sfd, char *buffer, size_t bfsize,
        ssize_t n, ssize_t offset, struct sockaddr *dst, int dp_c)
{
    struct desync_params dp = params.dp[dp_c];
    
    char *host = 0;
    int len = 0, type = 0;
    int fa = get_family(dst);
    // parse packet
    if ((len = parse_tls(buffer, n, &host))) {
        type = IS_HTTPS;
    }
    else if ((len = parse_http(buffer, n, &host, 0))) {
        type = IS_HTTP;
    }
    if (len && host) {
        LOG(LOG_S, "host: %.*s (%zd)\n",
            len, host, host - buffer);
    }
    // modify packet
    if (type == IS_HTTP && dp.mod_http) {
        LOG(LOG_S, "modify HTTP: n=%zd\n", n);
        if (mod_http(buffer, n, dp.mod_http)) {
            LOG(LOG_E, "mod http error\n");
            return -1;
        }
    }
    else if (type == IS_HTTPS && dp.tlsrec_n) {
        long lp = 0;
        for (int i = 0; i < dp.tlsrec_n; i++) {
            struct part part = dp.tlsrec[i];
            
            long pos = part.pos + i * 5;
            if (part.flag == OFFSET_SNI) {
                pos += (host - buffer - 5);
            }
            else if (pos < 0) {
                pos += n;
            }
            if (pos < lp) {
                LOG(LOG_E, "tlsrec cancel: %ld < %ld\n", pos, lp);
                break;
            }
            if (!part_tls(buffer + lp, 
                    bfsize - lp, n - lp, pos - lp)) {
                LOG(LOG_E, "tlsrec error: pos=%ld, n=%zd\n", pos, n);
                break;
            }
            LOG(LOG_S, "tlsrec: pos=%ld, n=%zd\n", pos, n);
            n += 5;
            lp = pos + 5;
        }
    }
    // desync
    long lp = offset;
    
    for (int i = 0; i < dp.parts_n; i++) {
        struct part part = dp.parts[i];
        
        // change pos
        long pos = part.pos;
        if (part.flag == OFFSET_SNI) {
            if (type != IS_HTTPS) 
                continue;
            else 
                pos += (host - buffer);
        }
        else if (part.flag == OFFSET_HOST) {
            if (type != IS_HTTP) 
                continue;
            else 
                pos += (host - buffer);
        }
        else if (pos < 0) {
            pos += n;
        }
        // after EAGAIN
        if (pos <= offset) {
            continue;
        }
        else if (pos <= 0 || pos >= n || pos <= lp) {
            LOG(LOG_E, "split cancel: pos=%ld-%ld, n=%zd\n", lp, pos, n);
            break;
        }
        // send part
        ssize_t s = 0;
        switch (part.m) {
            #ifdef FAKE_SUPPORT
            case DESYNC_FAKE:
                s = send_fake(sfd, 
                    buffer + lp, type, pos - lp, fa, &dp);
                break;
            #endif
            case DESYNC_DISORDER:
                s = send_disorder(sfd, 
                    buffer + lp, pos - lp, fa);
                break;
            
            case DESYNC_OOB:
                s = send_oob(sfd, 
                    buffer + lp, n - lp, pos - lp);
                wait_send_if_support(sfd);
                break;
                
            case DESYNC_SPLIT:
            case DESYNC_NONE:
                s = send(sfd, buffer + lp, pos - lp, 0);
                wait_send_if_support(sfd);
                break;
                
            default:
                return -1;
        }
        LOG(LOG_S, "split: pos=%ld-%ld (%zd), m: %s\n", lp, pos, s, demode_str[part.m]);
        
        if (s < 0) {
            if (get_e() == EAGAIN) {
                return lp;
            }
            return -1;
        } 
        else if (s != (pos - lp)) {
            LOG(LOG_E, "%zd != %ld\n", s, pos - lp);
            return lp + s;
        }
        lp = pos;
    }
    // send all/rest
    if (lp < n) {
        LOG((lp ? LOG_S : LOG_L), "send: pos=%ld-%zd\n", lp, n);
        if (send(sfd, buffer + lp, n - lp, 0) < 0) {
            if (get_e() == EAGAIN) {
                return lp;
            }
            uniperror("send");
            return -1;
        }
    }
    return n;
}


ssize_t desync_udp(int sfd, char *buffer, size_t bfsize,
        ssize_t n, struct sockaddr *dst, int dp_c)
{
    struct desync_params *dp = &params.dp[dp_c];
    int fa = get_family(dst);
    
    if (dp->udp_fake_count != 0) {
        struct packet pkt;
        if (dp->fake_data.data) {
            pkt = dp->fake_data;
        }
        else {
            pkt = fake_udp;
        }

        int bttl = dp->ttl ? dp->ttl : 8;
        if (setttl(sfd, bttl, fa) < 0) {
            return -1;
        }
        for (int i = 0; i < dp->udp_fake_count; i++) {
            ssize_t len = sendto(sfd, pkt.data, 
                pkt.size, 0, dst, sizeof(struct sockaddr_in6));
            if (len < 0) {
                uniperror("send");
                return -1;
            }
        }
        if (setttl(sfd, params.def_ttl, fa) < 0) {
            return -1;
        }
    }
    return sendto(sfd, buffer, n, 0, 
        dst, sizeof(struct sockaddr_in6));
}
