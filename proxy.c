#include "proxy.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <assert.h>

#include "params.h"
#include "conev.h"
#include "extend.h"
#include "error.h"
#include "packets.h"

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    
    #define close(fd) closesocket(fd)
    #define SHUT_RDWR SD_BOTH
#else
    #include <errno.h>
    #include <unistd.h>
    #include <fcntl.h>
    
    #include <sys/socket.h>
    #include <arpa/inet.h>
    #include <netinet/tcp.h>
    #include <netdb.h>

    #if defined(__linux__) && defined(__GLIBC__)
        extern int accept4(int, struct sockaddr *__restrict, socklen_t *__restrict, int);
    #endif
    #ifdef __linux__
        /* For SO_ORIGINAL_DST only (which is 0x50) */
        #include "linux/netfilter_ipv4.h"
        #ifndef IP6T_SO_ORIGINAL_DST
        #define IP6T_SO_ORIGINAL_DST SO_ORIGINAL_DST
        #endif
    #endif
#endif


int server_fd;

static void on_cancel(int sig) {
    shutdown(server_fd, SHUT_RDWR);
}

static void on_hup(int sig) {
    FILE *f;
    if (!strcmp(params.cache_file, "-"))
        f = stdout;
    else
        f = fopen(params.cache_file, "w");
    if (!f) {
        perror("fopen");
        return;
    }
    LOG(LOG_S, "dump cache\n");
    dump_cache(params.mempool, f);
    fclose(f);
}


void map_fix(union sockaddr_u *addr, char f6)
{
    struct {
        uint64_t o64;
        uint16_t o16;
        uint16_t t16;
        uint32_t o32;
    } *ipv6m = (void *)&addr->in6.sin6_addr;
    
    if (addr->sa.sa_family == AF_INET && f6) {
        addr->sa.sa_family = AF_INET6;
        ipv6m->o32 = *(uint32_t *)(&addr->in.sin_addr);
        ipv6m->o64 = 0;
        ipv6m->o16 = 0;
        ipv6m->t16 = 0xffff;
    } 
    else if (!ipv6m->o64 && !ipv6m->o16 &&
            ipv6m->t16 == 0xffff && !f6) {
        addr->sa.sa_family = AF_INET;
        const struct in_addr *sin_addr_ptr = (struct in_addr *) &ipv6m->o32;
        addr->in.sin_addr = *sin_addr_ptr;
    }
}


static inline char addr_equ(
        const union sockaddr_u *a, const union sockaddr_u *b)
{
    if (a->sa.sa_family == AF_INET) {
        return 
            *((const uint32_t *)(&a->in.sin_addr)) ==
            *((const uint32_t *)(&b->in.sin_addr));
    }
    return memcmp(&a->in6.sin6_addr, 
        &b->in6.sin6_addr, sizeof(b->in6.sin6_addr)) == 0;
}


static inline int nb_socket(int domain, int type)
{
    #ifdef __linux__
    int fd = socket(domain, type | SOCK_NONBLOCK, 0);
    #else
    int fd = socket(domain, type, 0);
    #endif
    if (fd < 0) {
        uniperror("socket");  
        return -1;
    }
    #ifdef _WIN32
    unsigned long mode = 1;
    if (ioctlsocket(fd, FIONBIO, &mode) < 0) {
        uniperror("ioctlsocket");
        close(fd);
        return -1;
    }
    #else
    #ifndef __linux__
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        uniperror("fcntl");
        close(fd);
        return -1;
    }
    #endif
    #endif
    return fd;
}


static int resolve(const char *chost, int len, 
        union sockaddr_u *addr, int type) 
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = type;
    hints.ai_flags = AI_ADDRCONFIG;
    if (!params.resolve)
        hints.ai_flags |= AI_NUMERICHOST;
    hints.ai_family = params.ipv6 ? AF_UNSPEC : AF_INET;
    
    char host[len + 1];
    host[len] = 0;
    memcpy(host, chost, len);
    
    LOG(LOG_S, "resolve: %s\n", host);
    
    if (getaddrinfo(host, 0, &hints, &res) || !res) {
        return -1;
    }
    memcpy(addr, res->ai_addr, SA_SIZE(res->ai_addr));
    freeaddrinfo(res);
    
    return 0;
}


static int auth_socks5(int fd, const char *buffer, ssize_t n)
{
    if (n <= 2 || (uint8_t)buffer[1] != (n - 2)) {
        return -1;
    }
    uint8_t c = S_AUTH_BAD;
    for (long i = 2; i < n; i++)
        if (buffer[i] == S_AUTH_NONE) {
            c = S_AUTH_NONE;
            break;
        }
    uint8_t a[2] = { S_VER5, c };
    if (send(fd, (char *)a, sizeof(a), 0) < 0) {
        uniperror("send");
        return -1;
    }
    return c != S_AUTH_BAD ? 0 : -1;
}


static int resp_s5_error(int fd, int e)
{
    struct s5_rep s5r = { 
        .ver = 0x05, .code = (uint8_t )e, 
        .atp = S_ATP_I4
    };
    return send(fd, (char *)&s5r, sizeof(s5r), 0);
}


static int resp_error(int fd, int e, int flag)
{
    if (flag == FLAG_S4) {
        struct s4_req s4r = { 
            .cmd = e ? S4_ER : S4_OK
        };
        return send(fd, (char *)&s4r, sizeof(s4r), 0);
    }
    else if (flag == FLAG_S5) {
        switch (unie(e)) {
            case 0: e = S_ER_OK;
                break;
            case ECONNREFUSED: 
                e = S_ER_CONN;
                break;
            case EHOSTUNREACH:
            case ETIMEDOUT: 
                e = S_ER_HOST;
                break;
            case ENETUNREACH: 
                e = S_ER_NET;
                break;
            default: e = S_ER_GEN;
        }
        return resp_s5_error(fd, e);
    }
    else if (flag == FLAG_HTTP) {
        if (!e) {
            static const char r[] = "HTTP/1.1 200 OK\r\n\r\n";
            return send(fd, r, sizeof(r) - 1, 0);
        }
        static const char r[] = "HTTP/1.1 503 Fail\r\n\r\n";
        return send(fd, r, sizeof(r) - 1, 0);
    }
    #ifdef __linux__
    if (params.transparent &&
            (e == ECONNREFUSED || e == ETIMEDOUT)) {
        struct linger l = { .l_onoff = 1 };
        if (setsockopt(fd, 
                SOL_SOCKET, SO_LINGER, &l, sizeof(l)) < 0) {
            uniperror("setsockopt SO_LINGER");
            return -1;
        }
    }
    #endif
    return 0;
}


static int s4_get_addr(const char *buff, 
        size_t n, union sockaddr_u *dst)
{
    if (n < sizeof(struct s4_req) + 1) {
        return -1;
    }
    const struct s4_req *r = (const struct s4_req *)buff;
    
    if (r->cmd != S_CMD_CONN) {
        return -1;
    }
    if (ntohl(r->i4.s_addr) <= 255) {
        if (!params.resolve || buff[n - 1] != 0) {
            return -1;
        }
        char *id_end = strchr(buff + sizeof(*r), 0);
        if (!id_end) {
            return -1;
        }
        int len = (buff + n - id_end) - 2;
        if (len < 3 || len > 255) {
            return -1;
        }
        if (resolve(id_end + 1, len, dst, SOCK_STREAM)) {
            LOG(LOG_E, "not resolved: %.*s\n", len, id_end + 1);
            return -1;
        }
    }
    else {
        dst->in.sin_family = AF_INET;
        dst->in.sin_addr = r->i4;
    }
    dst->in.sin_port = r->port;
    return 0;
}


static int s5_get_addr(const char *buffer, 
        size_t n, union sockaddr_u *addr, int type) 
{
    if (n < S_SIZE_MIN) {
        LOG(LOG_E, "ss: request too small\n");
        return -S_ER_GEN;
    }
    const struct s5_req *r = (const struct s5_req *)buffer;
    
    size_t o = (r->atp == S_ATP_I4 ? S_SIZE_I4 : 
            (r->atp == S_ATP_ID ? r->dst.id.len + S_SIZE_ID : 
            (r->atp == S_ATP_I6 ? S_SIZE_I6 : 0)));
    if (n < o)  {
        LOG(LOG_E, "ss: bad request\n");
        return -S_ER_GEN;
    }
    switch (r->atp) {
        case S_ATP_I4:
            addr->in.sin_family = AF_INET;
            addr->in.sin_addr = r->dst.i4.ip;
            break;
        
        case S_ATP_ID:
            if (!params.resolve) {
                return -S_ER_ATP;
            }
            if (r->dst.id.len < 3 || 
                    resolve(r->dst.id.domain, r->dst.id.len, addr, type)) {
                LOG(LOG_E, "not resolved: %.*s\n", r->dst.id.len, r->dst.id.domain);
                return -S_ER_HOST;
            }
            break;
        
        case S_ATP_I6:
            if (!params.ipv6)
                return -S_ER_ATP;
            else {
                addr->in6.sin6_family = AF_INET6;
                addr->in6.sin6_addr = r->dst.i6.ip;
            }
    }
    memcpy(&addr->in.sin_port, &buffer[o - 2], sizeof(uint16_t));
    return o;
}


int s5_set_addr(char *buffer, size_t n,
        const union sockaddr_u *addr, char end)
{
    struct s5_req *r = (struct s5_req *)buffer;
    if (n < S_SIZE_I4) {
        return -1;
    }
    if (addr->sa.sa_family == AF_INET) {
        if (end) {
            r = (struct s5_req *)(buffer - S_SIZE_I4);
        }
        r->atp = S_ATP_I4;
        r->dst.i4.ip = addr->in.sin_addr;
        r->dst.i4.port = addr->in.sin_port;
        return S_SIZE_I4;
    } else {
        if (n < S_SIZE_I6) {
            return -1;
        }
        if (end) {
            r = (struct s5_req *)(buffer - S_SIZE_I6);
        }
        r->atp = S_ATP_I6;
        r->dst.i6.ip = addr->in6.sin6_addr;
        r->dst.i6.port = addr->in6.sin6_port;
        return S_SIZE_I6;
    }
    return 0;
}


static int http_get_addr(
        const char *buff, size_t n, union sockaddr_u *dst)
{
    char *host = 0;
    uint16_t port = 0;
    int host_len = parse_http(buff, n, &host, &port);
    
    if (host_len < 3 || host_len > 255) {
        return -1;
    }
    if (resolve(host, host_len, dst, SOCK_STREAM)) {
        LOG(LOG_E, "not resolved: %.*s\n", host_len, host);
        return -1;
    }
    dst->in.sin_port = htons(port);
    return 0;
}


static int remote_sock(union sockaddr_u *dst, int type)
{
    if (params.baddr.sa.sa_family == AF_INET6) {
        map_fix(dst, 6);
    } else {
        map_fix(dst, 0);
    }
    if (dst->sa.sa_family != params.baddr.sa.sa_family) {
        LOG(LOG_E, "different addresses family\n");
        return -1;
    }
    int sfd = nb_socket(dst->sa.sa_family, type);
    if (sfd < 0) {
        uniperror("socket");  
        return -1;
    }
    if (socket_mod(sfd) < 0) {
        close(sfd);
        return -1;
    }
    if (dst->sa.sa_family == AF_INET6) {
        int no = 0;
        if (setsockopt(sfd, IPPROTO_IPV6,
                IPV6_V6ONLY, (char *)&no, sizeof(no))) {
            uniperror("setsockopt IPV6_V6ONLY");
            close(sfd);
            return -1;
        }
    }
    if (bind(sfd, (struct sockaddr *)&params.baddr, 
            SA_SIZE(&params.baddr)) < 0) {
        uniperror("bind");  
        close(sfd);
        return -1;
    }
    return sfd;
}


int create_conn(struct poolhd *pool,
        struct eval *val, const union sockaddr_u *dst, evcb_t next)
{
    union sockaddr_u addr = *dst;
    
    int sfd = remote_sock(&addr, SOCK_STREAM);
    if (sfd < 0) {
        return -1;
    }
    #ifdef __linux__
    int syn_count = 1;
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_SYNCNT, (char *)&syn_count, sizeof(syn_count))) {
        uniperror("setsockopt TCP_SYNCNT");
        close(sfd);
        return -1;
    }
    #ifdef TCP_FASTOPEN_CONNECT
    int yes = 1;
    if (params.tfo && setsockopt(sfd, IPPROTO_TCP,
            TCP_FASTOPEN_CONNECT, (char *)&yes, sizeof(yes))) {
        uniperror("setsockopt TCP_FASTOPEN_CONNECT");
        close(sfd);
        return -1;
    }
    #endif
    #endif
    int one = 1;
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_NODELAY, (char *)&one, sizeof(one))) {
        uniperror("setsockopt TCP_NODELAY");
        close(sfd);
        return -1;
    }
    if (LOG_ENABLED) {
        INIT_ADDR_STR((*dst));
        LOG(LOG_S, "new conn: fd=%d, pair=%d, addr=%s:%d\n", 
            sfd, val->fd, ADDR_STR, ntohs(dst->in.sin_port));
    }
    int status = connect(sfd, &addr.sa, SA_SIZE(&addr));
    if (status == 0 && params.tfo) {
        LOG(LOG_S, "TFO supported!\n");
    }
    if (status < 0 && 
            get_e() != EINPROGRESS && get_e() != EAGAIN) {
        uniperror("connect");
        close(sfd);
        return -1;
    }
    struct eval *pair = add_event(pool, next, sfd, POLLOUT);
    if (!pair) {
        close(sfd);
        return -1;
    }
    if (mod_etype(pool, val, 0) < 0) {
        uniperror("mod_etype");
        return -1;
    }
    val->pair = pair;
    pair->pair = val;
    #ifdef __NetBSD__
    pair->addr = addr;
    #else
    pair->addr = *dst;
    #endif
    pair->flag = FLAG_CONN;
    val->cb = &on_ignore;
    return 0;
}


static int udp_associate(struct poolhd *pool, 
        struct eval *val, const union sockaddr_u *dst)
{
    union sockaddr_u addr = *dst;
    
    int ufd = remote_sock(&addr, SOCK_DGRAM);
    if (ufd < 0) {
        return -1;
    }
    struct eval *pair = add_event(pool, &on_udp_tunnel, ufd, POLLIN);
    if (!pair) {
        close(ufd);
        return -1;
    }
    //
    socklen_t sz = sizeof(addr);
    
    if (getsockname(val->fd, &addr.sa, &sz)) {
        uniperror("getsockname");
        return -1;
    }
    addr.in.sin_port = 0;
    
    int cfd = nb_socket(addr.sa.sa_family, SOCK_DGRAM);
    if (cfd < 0) {
        uniperror("socket");
        del_event(pool, pair);
        return -1;
    }
    if (bind(cfd, &addr.sa, SA_SIZE(&addr)) < 0) {
        uniperror("bind");
        del_event(pool, pair);
        close(cfd);
        return -1;
    }
    struct eval *client = add_event(pool, &on_udp_tunnel, cfd, POLLIN);
    if (!client) {
        del_event(pool, pair);
        close(cfd);
        return -1;
    }
    if (LOG_ENABLED) {
        INIT_ADDR_STR((*dst));
        LOG(LOG_S, "udp associate: fds=%d,%d,%d addr=%s:%d\n", 
            ufd, cfd, val->fd, ADDR_STR, ntohs(dst->in.sin_port));
    }
    val->cb = &on_ignore;
    val->pair = client;
    client->pair = pair;
    pair->pair = val;
    
    client->flag = FLAG_CONN;
    client->addr = val->addr;
    client->addr.in.sin_port = 0;
    
    sz = sizeof(addr);
    if (getsockname(cfd, &addr.sa, &sz)) {
        uniperror("getsockname");
        return -1;
    }
    struct s5_req s5r = { 
        .ver = 0x05 
    };
    int len = s5_set_addr((char *)&s5r, sizeof(s5r), &addr, 0);
    if (len < 0) {
        return -1;
    }
    if (send(val->fd, (char *)&s5r, len, 0) < 0) {
        uniperror("send");
        return -1;
    }
    if (mod_etype(pool, val, POLLRDHUP)) {
        uniperror("mod_etype");
        return -1;
    }
    return 0;
}

#ifdef __linux__
static inline int transp_conn(struct poolhd *pool, struct eval *val)
{
    union sockaddr_u remote, self;
    socklen_t rlen = sizeof(remote), slen = sizeof(self);
    if (getsockopt(val->fd, IPPROTO_IP,
            SO_ORIGINAL_DST, &remote, &rlen) != 0)
    {
        if (getsockopt(val->fd, IPPROTO_IPV6,
                IP6T_SO_ORIGINAL_DST, &remote, &rlen) != 0) {
            uniperror("getsockopt SO_ORIGINAL_DST");
            return -1;
        }
    }
    if (getsockname(val->fd, &self.sa, &slen) < 0) {
        uniperror("getsockname");
        return -1;
    }
    if (self.sa.sa_family == remote.sa.sa_family && 
            self.in.sin_port == remote.in.sin_port && 
                addr_equ(&self, &remote)) {
        LOG(LOG_E, "connect to self, ignore\n");
        return -1;
    }
    int error = connect_hook(pool, val, &remote, &on_connect);
    if (error) {
        uniperror("connect_hook");
        return -1;
    }
    return 0;
}
#endif

static int on_accept(struct poolhd *pool, struct eval *val, int et)
{
    union sockaddr_u client;
    struct eval *rval;
    
    while (1) {
        socklen_t len = sizeof(client);
        #ifdef __linux__
        int c = accept4(val->fd, &client.sa, &len, SOCK_NONBLOCK);
        #else
        int c = accept(val->fd, &client.sa, &len);
        #endif
        if (c < 0) {
            if (get_e() == EAGAIN ||
                    get_e() == EINPROGRESS)
                break;
            uniperror("accept");
            pool->brk = 1;
            return -1;
        }
        LOG(LOG_S, "accept: fd=%d\n", c);
        #ifndef __linux__
        #ifdef _WIN32
        unsigned long mode = 1;
        if (ioctlsocket(c, FIONBIO, &mode) < 0) {
            uniperror("ioctlsocket");
        #else
        if (fcntl(c, F_SETFL, O_NONBLOCK) < 0) {
            uniperror("fcntl");
        #endif
            close(c);
            continue;
        }
        #endif
        int one = 1;
        if (setsockopt(c, IPPROTO_TCP, TCP_NODELAY,
                (char *)&one, sizeof(one))) {
            uniperror("setsockopt TCP_NODELAY");
            close(c);
            continue;
        }
        if (!(rval = add_event(pool, &on_request, c, POLLIN))) {
            close(c);
            continue;
        }
        rval->addr = client;
        #ifdef __linux__
        if (params.transparent && transp_conn(pool, rval) < 0) {
            del_event(pool, rval);
            continue;
        }
        #endif
    }
    return 0;
}


int on_tunnel(struct poolhd *pool, struct eval *val, int etype)
{
    ssize_t n = 0;
    struct eval *pair = val->pair;
    
    if (etype & POLLOUT || etype == POLLTIMEOUT) {
        LOG(LOG_S, "pollout (fd=%d)\n", val->fd);
        val = pair;
        pair = val->pair;
    }
    if (val->buff) {
        if (etype & POLLHUP) {
            return -1;
        }
        n = val->buff->lock - val->buff->offset;
        
        bool wait = false;
        ssize_t sn = tcp_send_hook(pool, pair, val->buff, &val->buff->lock, &wait);
        if (sn < 0) {
            uniperror("send");
            return -1;
        }
        if (sn < n || wait) {
            val->buff->offset += sn;
            return 0;
        }
        buff_push(pool, val->buff);
        val->buff = 0;
        
        if (mod_etype(pool, val, POLLIN) ||
                mod_etype(pool, pair, POLLIN)) {
            uniperror("mod_etype");
            return -1;
        }
    }
    struct buffer *buff = buff_pop(pool, params.bfsize);
    if (!buff) {
        return -1;
    }
    val->buff = buff;
    do {
        n = tcp_recv_hook(pool, val, buff);
        //if (n < 0 && get_e() == EAGAIN) {
        if (n == 0) {
            break;
        }
        if (n < 0) {
            return -1;
        }
        
        bool wait = false;
        ssize_t sn = tcp_send_hook(pool, pair, buff, &n, &wait);
        if (sn < 0) {
            uniperror("send");
            return -1;
        }
        if (sn < n || wait) {
            if (sn < n) {
                LOG(LOG_S, "send: %zd != %zd (fd=%d)\n", sn, n, pair->fd);
            }
            else {
                LOG(LOG_S, "send: %zd, but not done yet (fd=%d)\n", sn, pair->fd);
            }
            
            buff->lock = n;
            buff->offset = sn;
            
            if (mod_etype(pool, val, 0) ||
                    mod_etype(pool, pair, !wait ? POLLOUT : 0)) {
                uniperror("mod_etype");
                return -1;
            }
            return 0;
        }
    } while (n == (ssize_t )buff->size);
    buff_push(pool, val->buff);
    val->buff = 0;
    return 0;
}


int on_udp_tunnel(struct poolhd *pool, struct eval *val, int et)
{
    struct buffer *buff = buff_ppop(pool, params.bfsize);
    if (!buff) {
        return -1;
    }
    char *data = buff->data;
    size_t data_len = buff->size;
    
    if (val->flag != FLAG_CONN) {
        data += S_SIZE_I6;
        data_len -= S_SIZE_I6;
    }
    union sockaddr_u addr = {0};
    struct eval *pair = val->flag == FLAG_CONN ?
        val->pair : val->pair->pair;
    
    do {
        socklen_t asz = sizeof(addr);
        
        ssize_t n = recvfrom(val->fd, data, data_len, 0, &addr.sa, &asz);
        if (n < 1) {
            if (n && get_e() == EAGAIN)
                break;
            uniperror("recv udp");
            return -1;
        }
        val->recv_count += n;
        if (val->round_sent == 0) {
            val->round_count++;
            val->round_sent += n;
            pair->round_sent = 0;
        }
        ssize_t ns;
        
        if (val->flag == FLAG_CONN) {
            if (!val->addr.in.sin_port) {
                if (!addr_equ(&addr, &val->addr)) {
                    return 0;
                }
                if (connect(val->fd, &addr.sa, SA_SIZE(&addr)) < 0) {
                    uniperror("connect");
                    return -1;
                }
                val->addr = addr;
            }
            if (*(data + 2) != 0) { // frag
                continue;
            }
            int offs = s5_get_addr(data, n, &addr, SOCK_DGRAM);
            if (offs < 0) {
                LOG(LOG_E, "udp parse error\n");
                return -1;
            }
            if (!pair->addr.in.sin_port) {
                if (params.baddr.sa.sa_family == AF_INET6) {
                    map_fix(&addr, 6);
                }
                if (params.baddr.sa.sa_family != addr.sa.sa_family) {
                    return -1;
                }
                INIT_ADDR_STR((addr));
                LOG(LOG_S, "udp addr: fd=%d, addr=%s:%d\n", 
                    val->fd, ADDR_STR, ntohs(addr.in.sin_port));
                    
                if (connect(pair->fd, &addr.sa, SA_SIZE(&addr)) < 0) {
                    uniperror("connect");
                    return -1;
                }
                pair->addr = addr;
            }
            ns = udp_hook(pair, data + offs, n - offs, &pair->addr);
        }
        else {
            map_fix(&addr, 0);
            memset(buff->data, 0, S_SIZE_I6);
            
            int offs = s5_set_addr(data, S_SIZE_I6, &addr, 1);
            if (offs < 0 || offs > S_SIZE_I6) {
                return -1;
            }
            ns = send(pair->fd, data - offs, offs + n, 0);
        }
        if (ns < 0) {
            uniperror("sendto");
            return -1;
        }
    } while(1);
    return 0;
}


int on_request(struct poolhd *pool, struct eval *val, int et)
{
    union sockaddr_u dst = {0};
    struct buffer *buff = buff_ppop(pool, params.bfsize);
    if (!buff) {
        return -1;
    }
    ssize_t n = recv(val->fd, buff->data, buff->size, 0);
    if (n < 1) {
        if (n) uniperror("ss recv");
        return -1;
    }
    int error = 0;
    
    if (*buff->data == S_VER5) {
        if (val->flag != FLAG_S5) {
            if (auth_socks5(val->fd, buff->data, n)) {
                return -1;
            }
            val->flag = FLAG_S5;
            return 0;
        }
        if (n < S_SIZE_MIN) {
            LOG(LOG_E, "ss: request too small (%zd)\n", n);
            return -1;
        }
        struct s5_req *r = (struct s5_req *)buff->data;
        int s5e = 0;
        switch (r->cmd) {
            case S_CMD_CONN:
                s5e = s5_get_addr(buff->data, n, &dst, SOCK_STREAM);
                if (s5e >= 0) {
                    error = connect_hook(pool, val, &dst, &on_connect);
                }
                break;
            case S_CMD_AUDP:
                if (params.udp) {
                    s5e = s5_get_addr(buff->data, n, &dst, SOCK_DGRAM);
                    if (s5e >= 0) {
                        error = udp_associate(pool, val, &dst);
                    }
                    break;
                }
                __attribute__((fallthrough));
            default:
                LOG(LOG_E, "ss: unsupported cmd: 0x%x\n", r->cmd);
                s5e = -S_ER_CMD;
        }
        if (s5e < 0) {
            if (resp_s5_error(val->fd, -s5e) < 0)
                uniperror("send");
            return -1;
        }
    }
    else if (*buff->data == S_VER4) {
        val->flag = FLAG_S4;
        
        error = s4_get_addr(buff->data, n, &dst);
        if (error) {
            if (resp_error(val->fd, error, FLAG_S4) < 0)
                uniperror("send");
            return -1;
        }
        error = connect_hook(pool, val, &dst, &on_connect);
    }
    else if (params.http_connect
            && n > 7 && !memcmp(buff->data, "CONNECT", 7)) {
        val->flag = FLAG_HTTP;
        
        if (http_get_addr(buff->data, n, &dst)) {
            return -1;
        }
        error = connect_hook(pool, val, &dst, &on_connect);
    }
    else {
        LOG(LOG_E, "ss: invalid version: 0x%x (%zd)\n", *buff->data, n);
        return -1;
    }
    if (error) {
        int en = get_e();
        if (resp_error(val->fd, en ? en : error, val->flag) < 0)
            uniperror("send");
        LOG(LOG_S, "ss error: %d\n", en);
        return -1;
    }
    return 0;
}


int on_connect(struct poolhd *pool, struct eval *val, int et)
{
    int error = 0;
    socklen_t len = sizeof(error);
    if (et & POLLERR) {
        if (getsockopt(val->fd, SOL_SOCKET, 
                SO_ERROR, (char *)&error, &len)) {
            uniperror("getsockopt SO_ERROR");
            return -1;
        }
        switch (error) {
        case ECONNRESET:
        case ECONNREFUSED:
        case ETIMEDOUT:
        case EHOSTUNREACH:
            if (on_torst(pool, val) == 0) {
                return 0;
            }
        }
    }
    else {
        if (mod_etype(pool, val, POLLIN) ||
                mod_etype(pool, val->pair, POLLIN)) {
            uniperror("mod_etype");
            return -1;
        }
        val->cb = &on_tunnel;
        val->pair->cb = &on_tunnel;
    }
    if (resp_error(val->pair->fd,
            error, val->pair->flag) < 0) {
        uniperror("send");
        return -1;
    }
    return error ? -1 : 0;
}


int on_ignore(struct poolhd *pool, struct eval *val, int etype)
{
    return (etype & (POLLHUP | POLLERR | POLLRDHUP)) ? -1 : 0;
}


int start_event_loop(int srvfd)
{
    server_fd = srvfd;
    
    struct poolhd *pool = init_pool(params.max_open * 2 + 1);
    if (!pool) {
        close(srvfd);
        return -1;
    }
    if (!add_event(pool, &on_accept, srvfd, POLLIN)) {
        destroy_pool(pool);
        close(srvfd);
        return -1;
    }
    loop_event(pool);
    
    LOG(LOG_S, "exit\n");
    destroy_pool(pool);
    return 0;
}


int listen_socket(const union sockaddr_u *srv)
{
    int srvfd = nb_socket(srv->sa.sa_family, SOCK_STREAM);
    if (srvfd < 0) {
        uniperror("socket");  
        return -1;  
    }
    int opt = 1;
    if (setsockopt(srvfd, SOL_SOCKET, 
            SO_REUSEADDR, (char *)&opt, sizeof(opt)) == -1) {
        uniperror("setsockopt");
        close(srvfd);
        return -1;
    }
    if (bind(srvfd, &srv->sa, SA_SIZE(srv)) < 0) {
        uniperror("bind");  
        close(srvfd);
        return -1;
    }
    if (listen(srvfd, 10)) {
        uniperror("listen");
        close(srvfd);
        return -1;
    }
    return srvfd;
}


int run(const union sockaddr_u *srv)
{
    #ifdef SIGPIPE
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        uniperror("signal SIGPIPE!");
    #endif
    signal(SIGINT, on_cancel);
    signal(SIGTERM, on_cancel);
    signal(SIGHUP, on_hup);
    
    int fd = listen_socket(srv);
    if (fd < 0) {
        return -1;
    }
    return start_event_loop(fd);
}
