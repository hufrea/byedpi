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
    #include <linux/tcp.h>
    #include <sys/sendfile.h>
    #include <linux/filter.h>
    #include <sys/syscall.h>
    
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

#ifdef __linux__
int drop_sack(int fd)
{
    struct sock_filter code[] = {
        { 0x30, 0, 0, 0x0000000c },
        { 0x74, 0, 0, 0x00000004 },
        { 0x35, 0, 3, 0x0000000b },
        { 0x30, 0, 0, 0x00000022 },
        { 0x15, 0, 1, 0x00000005 },
        { 0x6,  0, 0, 0x00000000 },
        { 0x6,  0, 0, 0x00040000 },
    };
    struct sock_fprog bpf = {
        .len = sizeof(code)/sizeof(*code),
        .filter = code
    };
    if (setsockopt(fd, SOL_SOCKET, 
            SO_ATTACH_FILTER, (char *)&bpf, sizeof(bpf)) == -1) {
        uniperror("setsockopt SO_ATTACH_FILTER");
        return -1;
    }
    return 0;
}
#endif


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
        struct tcp_info tcpi = {};
        socklen_t ts = sizeof(tcpi);
        
        if (getsockopt(sfd, IPPROTO_TCP,
                TCP_INFO, (char *)&tcpi, &ts) < 0) {
            perror("getsockopt TCP_INFO");
            break;
        }
        if (tcpi.tcpi_state != 1) {
            LOG(LOG_E, "state: %d\n", tcpi.tcpi_state);
            return;
        }
        size_t s = (char *)&tcpi.tcpi_notsent_bytes - (char *)&tcpi.tcpi_state;
        if (ts < s) {
            LOG(LOG_E, "tcpi_notsent_bytes not provided\n");
            params.wait_send = 0;
            break;
        }
        if (tcpi.tcpi_notsent_bytes == 0) {
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

#ifdef FAKE_SUPPORT
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
    if (opt->fake_offset) {
        if (pkt.size > opt->fake_offset) { 
            pkt.size -= opt->fake_offset;
            pkt.data += opt->fake_offset;
        }
        else pkt.size = 0;
    }
    
    int ffd = memfd_create("name", 0);
    if (ffd < 0) {
        uniperror("memfd_create");
        return -1;
    }
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
        memcpy(p, pkt.data, pkt.size < pos ? pkt.size : pos);
        
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
        
        len = sendfile(sfd, ffd, 0, pos);
        if (len < 0) {
            uniperror("sendfile");
            break;
        }
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
    if (opt->fake_offset) {
        if (psz > opt->fake_offset) { 
            psz -= opt->fake_offset;
            pkt.data += opt->fake_offset;
        }
        else psz = 0;
    }
    
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
#endif

ssize_t send_oob(int sfd, char *buffer,
        ssize_t n, long pos, char *c)
{
    char rchar = buffer[pos];
    buffer[pos] = c[1] ? c[0] : 'a';
    
    ssize_t len = send(sfd, buffer, pos + 1, MSG_OOB);
    buffer[pos] = rchar;
    
    if (len < 0) {
        uniperror("send");
        return -1;
    }
    wait_send_if_support(sfd);
    
    len--;
    if (len != pos) {
        return len;
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
    else wait_send_if_support(sfd);
    
    if (setttl(sfd, params.def_ttl, fa) < 0) {
        return -1;
    }
    return len;
}


ssize_t send_late_oob(int sfd, char *buffer,
        ssize_t n, long pos, int fa, char *c)
{
    int bttl = 1;
    
    if (setttl(sfd, bttl, fa) < 0) {
        return -1;
    }
    ssize_t len = send_oob(sfd, buffer, n, pos, c);
    if (len < 0) {
        uniperror("send");
    }
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
    #ifdef __linux__
    if (dp.drop_sack && drop_sack(sfd)) {
        return -1;
    }
    #endif
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
        else if (pos < 0 || part.flag == OFFSET_END) {
            pos += n;
        }
        // after EAGAIN
        if (offset && pos <= offset) {
            continue;
        }
        else if (pos < 0 || pos > n || pos < lp) {
            LOG(LOG_E, "split cancel: pos=%ld-%ld, n=%zd\n", lp, pos, n);
            break;
        }
        // send part
        ssize_t s = 0;
        switch (part.m) {
            #ifdef FAKE_SUPPORT
            case DESYNC_FAKE:
                if (pos != lp) s = send_fake(sfd, 
                    buffer + lp, type, pos - lp, fa, &dp);
                break;
            #endif
            case DESYNC_DISORDER:
                s = send_disorder(sfd, 
                    buffer + lp, pos - lp, fa);
                break;
            
            case DESYNC_OOB:
                s = send_oob(sfd, 
                    buffer + lp, n - lp, pos - lp, dp.oob_char);
                break;
                
            case DESYNC_DISOOB:
                s = send_late_oob(sfd, 
                    buffer + lp, n - lp, pos - lp, fa, dp.oob_char);
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


int post_desync(int sfd, int dp_c)
{
    struct desync_params *dp = &params.dp[dp_c];
    
    #ifdef __linux__
    if (dp->drop_sack) {
        if (setsockopt(sfd, SOL_SOCKET, 
                SO_DETACH_FILTER, &dp_c, sizeof(dp_c)) == -1) {
            uniperror("setsockopt SO_DETACH_FILTER");
            return -1;
        }
    }
    #endif
    return 0;
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
        if (dp->fake_offset) {
            if (pkt.size > dp->fake_offset) { 
                pkt.size -= dp->fake_offset;
                pkt.data += dp->fake_offset;
            }
            else pkt.size = 0;
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
