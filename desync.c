#define _GNU_SOURCE

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
    #include <linux/filter.h>
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

#define WAIT_LIMIT_MS 500
#define DEFAULT_TTL 8


int setttl(int fd, int ttl)
{
    int ret6 = setsockopt(fd, IPPROTO_IPV6,
        IPV6_UNICAST_HOPS, (char *)&ttl, sizeof(ttl));
    int ret4 = setsockopt(fd, IPPROTO_IP, 
        IP_TTL, (char *)&ttl, sizeof(ttl));
    
    if (ret4 && ret6) {
        uniperror("setttl");
        return -1;
    }
    return 0;
}


#ifdef __linux__
static int get_family(const struct sockaddr_in6 *dst)
{
    static const char map[12] = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
    if (dst->sin6_family == AF_INET6 
            && !memcmp(&dst->sin6_addr, map, sizeof(map))) {
        return AF_INET;
    }
    return dst->sin6_family;
}


static int drop_sack(int fd)
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


static inline void delay(long ms)
{
    struct timespec time = { 
         .tv_nsec = ms * 1e6
    };
    nanosleep(&time, 0);
}


static void wait_send_if_support(int sfd)
{
    int i = 0;
    for (; params.wait_send && i < WAIT_LIMIT_MS; i++) {
        struct tcp_info tcpi;
        socklen_t ts = sizeof(tcpi);
        
        if (getsockopt(sfd, IPPROTO_TCP,
                TCP_INFO, (char *)&tcpi, &ts) < 0) {
            perror("getsockopt TCP_INFO");
            break;
        }
        if (tcpi.tcpi_state != 1) {
            LOG(LOG_E, "state: %d\n", tcpi.tcpi_state);
            break;
        }
        if (ts <= offsetof(struct tcp_info, tcpi_notsent_bytes)) {
            LOG(LOG_E, "tcpi_notsent_bytes not provided\n");
            params.wait_send = 0;
            break;
        }
        if (tcpi.tcpi_notsent_bytes == 0) {
            break;
        }
        delay(1);
    }
    if (i) LOG(LOG_S, "waiting for send: %d ms\n", i);
}
#else
#define wait_send_if_support(sfd)
#endif


static struct packet get_tcp_fake(const char *buffer, size_t n,
        struct proto_info *info, const struct desync_params *opt)
{
    struct packet pkt;
    if (opt->fake_data.data) {
        pkt = opt->fake_data;
    }
    else {
        if (!info->type) {
            if (is_tls_chello(buffer, n)) info->type = IS_HTTPS;
            else if (is_http(buffer, n)) info->type = IS_HTTP;
        }
        pkt = info->type == IS_HTTP ? fake_http : fake_tls;
    }
    if (opt->fake_offset) {
        if (pkt.size > opt->fake_offset) { 
            pkt.size -= opt->fake_offset;
            pkt.data += opt->fake_offset;
        }
        else pkt.size = 0;
    }
    return pkt;
}


#ifdef __linux__
static ssize_t send_fake(int sfd, const char *buffer,
        long pos, const struct desync_params *opt, struct packet pkt)
{
    struct sockaddr_in6 addr = {};
    socklen_t addr_size = sizeof(addr);
    
    if (opt->md5sig || opt->ip_options) {
        if (getpeername(sfd, 
                (struct sockaddr *)&addr, &addr_size) < 0) {
            uniperror("getpeername");
            return -1;
        }
    }
    int fds[2];
    if (pipe(fds) < 0) {
        uniperror("pipe");
        return -1;
    }
    char *p = 0;
    ssize_t len = -1;
    
    while (1) {
        p = mmap(0, pos, PROT_WRITE | PROT_READ, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
        if (p == MAP_FAILED) {
            uniperror("mmap");
            p = 0;
            break;
        }
        memcpy(p, pkt.data, pkt.size < pos ? pkt.size : pos);
        
        if (setttl(sfd, opt->ttl ? opt->ttl : DEFAULT_TTL) < 0) {
            break;
        }
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
        if (opt->ip_options && get_family(&addr) == AF_INET 
            && setsockopt(sfd, IPPROTO_IP, IP_OPTIONS,
                opt->ip_options, opt->ip_options_len) < 0) {
            uniperror("setsockopt IP_OPTIONS");
            break;
        }
        struct iovec vec = { .iov_base = p, .iov_len = pos };
        
        len = vmsplice(fds[1], &vec, 1, SPLICE_F_GIFT);
        if (len < 0) {
            uniperror("vmsplice");
            break;
        }
        len = splice(fds[0], 0, sfd, 0, len, 0);
        if (len < 0) {
            uniperror("splice");
            break;
        }
        wait_send_if_support(sfd);
        memcpy(p, buffer, pos);
        
        if (setttl(sfd, params.def_ttl) < 0) {
            break;
        }
        if (opt->ip_options && get_family(&addr) == AF_INET 
            && setsockopt(sfd, IPPROTO_IP,
                IP_OPTIONS, opt->ip_options, 0) < 0) {
            uniperror("setsockopt IP_OPTIONS");
            break;
        }
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
        break;
    }
    if (p) munmap(p, pos);
    close(fds[0]);
    close(fds[1]);
    return len;
}
#endif

#ifdef _WIN32
OVERLAPPED ov = {};

static ssize_t send_fake(int sfd, const char *buffer,
        long pos, const struct desync_params *opt, struct packet pkt)
{
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
        DWORD wrtcnt = 0;
        if (!WriteFile(hfile, pkt.data, pkt.size < pos ? pkt.size : pos, &wrtcnt, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (pkt.size < pos) {
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
        if (setttl(sfd, opt->ttl ? opt->ttl : DEFAULT_TTL) < 0) {
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
        //Sleep(3);
        
        if (SetFilePointer(hfile, 0, 0, FILE_BEGIN) == INVALID_SET_FILE_POINTER) {
            uniperror("SetFilePointer");
            break;
        }
        if (!WriteFile(hfile, buffer, pos, &wrtcnt, 0)) {
            uniperror("WriteFile");
            break;
        }
        if (setttl(sfd, params.def_ttl) < 0) {
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

static ssize_t send_oob(int sfd, char *buffer,
        ssize_t n, long pos, const char *c)
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


static ssize_t send_disorder(int sfd, 
        const char *buffer, long pos)
{
    int bttl = 1;
    
    if (setttl(sfd, bttl) < 0) {
        return -1;
    }
    ssize_t len = send(sfd, buffer, pos, 0);
    if (len < 0) {
        uniperror("send");
    }
    else wait_send_if_support(sfd);
    
    if (setttl(sfd, params.def_ttl) < 0) {
        return -1;
    }
    return len;
}


static ssize_t send_late_oob(int sfd, char *buffer,
        ssize_t n, long pos, const char *c)
{
    int bttl = 1;
    
    if (setttl(sfd, bttl) < 0) {
        return -1;
    }
    ssize_t len = send_oob(sfd, buffer, n, pos, c);
    if (len < 0) {
        uniperror("send");
    }
    if (setttl(sfd, params.def_ttl) < 0) {
        return -1;
    }
    return len;
}


static void init_proto_info(
        const char *buffer, size_t n, struct proto_info *info)
{
    if (!info->init) {
        char *host = 0;
        
        if ((info->host_len = parse_tls(buffer, n, &host))) {
            info->type = IS_HTTPS;
        }
        else if ((info->host_len = parse_http(buffer, n, &host, 0))) {
            info->type = IS_HTTP;
        }
        info->host_pos = host ? host - buffer : 0;
        info->init = 1;
    }
}


static long gen_offset(long pos, int flag,
        const char *buffer, size_t n, long lp, struct proto_info *info)
{
    if (flag & (OFFSET_SNI | OFFSET_HOST)) {
        init_proto_info(buffer, n, info);
        
        if (!info->host_pos 
                || ((flag & OFFSET_SNI) && info->type != IS_HTTPS)) {
            return -1;
        }
        pos += info->host_pos;
        
        if (flag & OFFSET_END)
            pos += info->host_len;
        else if (flag & OFFSET_MID)
            pos += (info->host_len / 2);
        else if (flag & OFFSET_RAND)
            pos += (rand() % info->host_len);
    }
    else if (flag & OFFSET_RAND) {
        pos += lp + (rand() % (n - lp));
    }
    else if (flag & OFFSET_MID) {
        pos += (n / 2);
    }
    else if (pos < 0 || (flag & OFFSET_END)) {
        pos += n;
    }
    return pos;
}


static ssize_t tamp(char *buffer, size_t bfsize, ssize_t n, 
        const struct desync_params *dp, struct proto_info *info)
{
    if (dp->mod_http && is_http(buffer, n)) {
        LOG(LOG_S, "modify HTTP: n=%zd\n", n);
        if (mod_http(buffer, n, dp->mod_http)) {
            LOG(LOG_E, "mod http error\n");
        }
    }
    else if (dp->tlsrec_n && is_tls_chello(buffer, n)) {
        long lp = 0;
        struct part part;
        int i = 0, r = 0, rc = 0;
        
        for (; r > 0 || i < dp->tlsrec_n; rc++, r--) {
            if (r <= 0) {
                part = dp->tlsrec[i];
                r = part.r; i++;
            }
            long pos = rc * 5;
            pos += gen_offset(part.pos, 
                part.flag, buffer, n - pos, lp, info);
                
            if (part.pos < 0 || part.flag) {
                pos -= 5;
            }
            pos += (long )part.s * (part.r - r);
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
    return n;
}


ssize_t desync(int sfd, char *buffer, size_t bfsize,
        ssize_t n, ssize_t offset, const struct sockaddr *dst, int dp_c)
{
    struct desync_params dp = params.dp[dp_c];
    struct proto_info info = { 0 };
    
    if (offset == 0 && params.debug) {
        init_proto_info(buffer, n, &info);
        
        if (info.host_pos) {
            LOG(LOG_S, "host: %.*s (%d)\n",
                info.host_len, buffer + info.host_pos, info.host_pos);
        } else {
            INIT_HEX_STR(buffer, (n > 16 ? 16 : n));
            LOG(LOG_S, "bytes: %s (%zd)\n", HEX_STR, n);
        }
    }
    n = tamp(buffer, bfsize, n, &dp, &info);
    #ifdef __linux__
    if (!offset && dp.drop_sack && drop_sack(sfd)) {
        return -1;
    }
    #endif
    long lp = 0;
    struct part part;
    int i = 0, r = 0;
    
    for (; r > 0 || i < dp.parts_n; r--) {
        if (r <= 0) {
            part = dp.parts[i];
            r = part.r; i++;
        }
        long pos = gen_offset(part.pos, part.flag, buffer, n, lp, &info);
        pos += (long )part.s * (part.r - r);
        
        if (!(part.flag & OFFSET_START) && offset && pos <= offset) {
            LOG(LOG_S, "offset: %zd, skip\n", offset);
            continue;
        }
        if (pos < 0 || pos > n || pos < lp) {
            LOG(LOG_E, "split cancel: pos=%ld-%ld, n=%zd\n", lp, pos, n);
            break;
        }
        
        ssize_t s = 0;
        switch (part.m) {
            #ifdef FAKE_SUPPORT
            case DESYNC_FAKE:
                if (pos != lp) s = send_fake(sfd, 
                    buffer + lp, pos - lp, &dp, get_tcp_fake(buffer, n, &info, &dp));
                break;
            #endif
            case DESYNC_DISORDER:
                s = send_disorder(sfd, 
                    buffer + lp, pos - lp);
                break;
            
            case DESYNC_OOB:
                s = send_oob(sfd, 
                    buffer + lp, n - lp, pos - lp, dp.oob_char);
                break;
                
            case DESYNC_DISOOB:
                s = send_late_oob(sfd, 
                    buffer + lp, n - lp, pos - lp, dp.oob_char);
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
        ssize_t n, const struct sockaddr *dst, int dp_c)
{
    struct desync_params *dp = &params.dp[dp_c];
    
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
        int bttl = dp->ttl ? dp->ttl : DEFAULT_TTL;
        if (setttl(sfd, bttl) < 0) {
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
        if (setttl(sfd, params.def_ttl) < 0) {
            return -1;
        }
    }
    return sendto(sfd, buffer, n, 0, 
        dst, sizeof(struct sockaddr_in6));
}
