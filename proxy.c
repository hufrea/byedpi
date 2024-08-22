#define EID_STR

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

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    
    #define close(fd) closesocket(fd)
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
#endif

    
int NOT_EXIT = 1;

static void on_cancel(int sig) {
    NOT_EXIT = 0;
}


void map_fix(struct sockaddr_ina *addr, char f6)
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
        struct sockaddr_ina *a, struct sockaddr_ina *b)
{
    if (a->sa.sa_family == AF_INET) {
        return 
            *((uint32_t *)(&a->in.sin_addr)) ==
            *((uint32_t *)(&b->in.sin_addr));
    }
    return 
        *((uint64_t *)(&a->in6.sin6_addr)) ==
        *((uint64_t *)(&b->in6.sin6_addr)) &&
        *((uint64_t *)(&a->in6.sin6_addr) + 1) ==
        *((uint64_t *)(&b->in6.sin6_addr) + 1);
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


int resolve(char *host, int len, 
        struct sockaddr_ina *addr, int type) 
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = type;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = params.ipv6 ? AF_UNSPEC : AF_INET;
    
    char rchar = host[len];
    host[len] = '\0';
    
    if (getaddrinfo(host, 0, &hints, &res) || !res) {
        host[len] = rchar;
        return -1;
    }
    if (res->ai_addr->sa_family == AF_INET6)
        addr->in6 = *(struct sockaddr_in6 *)res->ai_addr;
    else
        addr->in = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);
    
    host[len] = rchar;
    return 0;
}


int auth_socks5(int fd, char *buffer, ssize_t n)
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
    buffer[1] = c;
    if (send(fd, buffer, 2, 0) < 0) {
        uniperror("send");
        return -1;
    }
    return c != S_AUTH_BAD ? 0 : -1;
}


int resp_s5_error(int fd, int e)
{
    struct s5_rep s5r = { 
        .ver = 0x05, .code = (uint8_t )e, 
        .atp = S_ATP_I4
    };
    return send(fd, (char *)&s5r, sizeof(s5r), 0);
}


int resp_error(int fd, int e, int flag)
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
    return 0;
}


int s4_get_addr(char *buff, size_t n,
        struct sockaddr_ina *dst)
{
    if (n < sizeof(struct s4_req) + 1) {
        return -1;
    }
    struct s4_req *r = (struct s4_req *)buff;
    
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


int s5_get_addr(char *buffer, size_t n,
        struct sockaddr_ina *addr, int type) 
{
    if (n < S_SIZE_MIN) {
        LOG(LOG_E, "ss: request to small\n");
        return -S_ER_GEN;
    }
    struct s5_req *r = (struct s5_req *)buffer;
    
    size_t o = (r->atp == S_ATP_I4 ? S_SIZE_I4 : 
            (r->atp == S_ATP_ID ? r->id.len + S_SIZE_ID : 
            (r->atp == S_ATP_I6 ? S_SIZE_I6 : 0)));
    if (n < o)  {
        LOG(LOG_E, "ss: bad request\n");
        return -S_ER_GEN;
    }
    switch (r->atp) {
        case S_ATP_I4:
            addr->in.sin_family = AF_INET;
            addr->in.sin_addr = r->i4;
            break;
        
        case S_ATP_ID:
            if (!params.resolve) {
                return -S_ER_ATP;
            }
            if (r->id.len < 3 || 
                    resolve(r->id.domain, r->id.len, addr, type)) {
                LOG(LOG_E, "not resolved: %.*s\n", r->id.len, r->id.domain);
                return -S_ER_HOST;
            }
            break;
        
        case S_ATP_I6:
            if (!params.ipv6)
                return -S_ER_ATP;
            else {
                addr->in6.sin6_family = AF_INET6;
                addr->in6.sin6_addr = r->i6;
            }
    }
    memcpy(&addr->in.sin_port, &buffer[o - 2], sizeof(uint16_t));
    return o;
}


int s5_set_addr(char *buffer, size_t n,
        struct sockaddr_ina *addr, char end)
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
        r->i4 = addr->in.sin_addr;
        r->p4 = addr->in.sin_port;
        return S_SIZE_I4;
    } else {
        if (n < S_SIZE_I6) {
            return -1;
        }
        if (end) {
            r = (struct s5_req *)(buffer - S_SIZE_I6);
        }
        r->atp = S_ATP_I6;
        r->i6 = addr->in6.sin6_addr;
        r->p6 = addr->in6.sin6_port;
        return S_SIZE_I6;
    }
    return 0;
}


int create_conn(struct poolhd *pool,
        struct eval *val, struct sockaddr_ina *dst, int next)
{
    struct sockaddr_ina addr = *dst;
    
    if (params.baddr.sin6_family == AF_INET6) {
        map_fix(&addr, 6);
    } else {
        map_fix(&addr, 0);
    }
    if (addr.sa.sa_family != params.baddr.sin6_family) {
        LOG(LOG_E, "different addresses family\n");
        return -1;
    }
    int sfd = nb_socket(addr.sa.sa_family, SOCK_STREAM);
    if (sfd < 0) {
        uniperror("socket");  
        return -1;
    }
    if (socket_mod(sfd, &addr.sa) < 0) {
        close(sfd);
        return -1;
    }
    if (addr.sa.sa_family == AF_INET6) {
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
    val->pair = pair;
    pair->pair = val;
    #ifdef __NetBSD__
    pair->in6 = addr.in6;
    #else
    pair->in6 = dst->in6;
    #endif
    pair->flag = FLAG_CONN;
    val->type = EV_IGNORE;
    
    if (params.debug) {
        INIT_ADDR_STR((*dst));
        LOG(LOG_S, "new conn: fd=%d, addr=%s:%d\n", 
            val->pair->fd, ADDR_STR, ntohs(dst->in.sin_port));
    }
    return 0;
}


int udp_associate(struct poolhd *pool, 
        struct eval *val, struct sockaddr_ina *dst)
{
    struct sockaddr_ina addr = *dst;
    
    int ufd = nb_socket(params.baddr.sin6_family, SOCK_DGRAM);
    if (ufd < 0) {
        uniperror("socket");  
        return -1;
    }
    if (params.baddr.sin6_family == AF_INET6) {
        int no = 0;
        if (setsockopt(ufd, IPPROTO_IPV6,
                IPV6_V6ONLY, (char *)&no, sizeof(no))) {
            uniperror("setsockopt IPV6_V6ONLY");
            close(ufd);
            return -1;
        }
        map_fix(&addr, 6);
    }
    if (bind(ufd, (struct sockaddr *)&params.baddr, 
            SA_SIZE(&params.baddr)) < 0) {
        uniperror("bind");  
        close(ufd);
        return -1;
    }
    struct eval *pair = add_event(pool, EV_UDP_TUNNEL, ufd, POLLIN);
    if (!pair) {
        close(ufd);
        return -1;
    }
    if (dst->in6.sin6_port != 0) {
        if (socket_mod(ufd, &addr.sa) < 0) {
            del_event(pool, pair);
            return -1;
        }
        if (connect(ufd, &addr.sa, SA_SIZE(&addr)) < 0) {
            uniperror("connect");
            del_event(pool, pair);
            return -1;
        }
        pair->in6 = addr.in6;
    }
    if (params.debug) {
        INIT_ADDR_STR((*dst));
        LOG(LOG_S, "udp associate: fd=%d, addr=%s:%d\n", 
            ufd, ADDR_STR, ntohs(dst->in.sin_port));
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
    struct eval *client = add_event(pool, EV_UDP_TUNNEL, cfd, POLLIN);
    if (!pair) {
        del_event(pool, pair);
        close(cfd);
        return -1;
    }
    val->type = EV_IGNORE;
    val->pair = client;
    client->pair = pair;
    pair->pair = val;
    
    client->flag = FLAG_CONN;
    client->in6 = val->in6;
    client->in6.sin6_port = 0;
    
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
    if (mod_etype(pool, val, 0)) {
        uniperror("mod_etype");
        return -1;
    }
    return 0;
}


static inline int on_accept(struct poolhd *pool, struct eval *val)
{
    struct sockaddr_ina client;
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
        if (!(rval = add_event(pool, EV_REQUEST, c, POLLIN))) {
            close(c);
            continue;
        }
        rval->in6 = client.in6;
    }
    return 0;
}


int on_tunnel(struct poolhd *pool, struct eval *val, 
        char *buffer, size_t bfsize, int etype)
{
    ssize_t n = 0;
    struct eval *pair = val->pair;
    
    if (etype & POLLOUT) {
        LOG(LOG_S, "pollout (fd=%d)\n", val->fd);
        val = pair;
        pair = val->pair;
    }
    if (val->buff.data) {
        if (etype & POLLHUP) {
            return -1;
        }
        n = val->buff.size - val->buff.offset;
        
        ssize_t sn = send(pair->fd, 
            val->buff.data + val->buff.offset, n, 0);
        if (sn != n) {
            if (sn < 0 && get_e() != EAGAIN) {
                uniperror("send");
                return -1;
            }
            if (sn > 0)
                val->buff.offset += sn;
            return 0;
        }
        free(val->buff.data);
        val->buff.data = 0;
        val->buff.size = 0;
        val->buff.offset = 0;
        
        if (mod_etype(pool, val, POLLIN) ||
                mod_etype(pool, pair, POLLIN)) {
            uniperror("mod_etype");
            return -1;
        }
    }
    do {
        n = recv(val->fd, buffer, bfsize, 0);
        if (n < 0 && get_e() == EAGAIN) {
            break;
        }
        if (n < 1) {
            if (n) uniperror("recv");
            return -1;
        }
        val->recv_count += n;
        
        ssize_t sn = send(pair->fd, buffer, n, 0);
        if (sn != n) {
            if (sn < 0) {
                if (get_e() != EAGAIN) {
                    uniperror("send");
                    return -1;
                }
                sn = 0;
            }
            LOG(LOG_S, "send: %zd != %zd (fd: %d)\n", sn, n, pair->fd);
            assert(!(val->buff.size || val->buff.offset));
            
            val->buff.size = n - sn;
            if (!(val->buff.data = malloc(n - sn))) {
                uniperror("malloc");
                return -1;
            }
            memcpy(val->buff.data, buffer + sn, n - sn);
            
            if (mod_etype(pool, val, 0) ||
                    mod_etype(pool, pair, POLLOUT)) {
                uniperror("mod_etype");
                return -1;
            }
            break;
        }
    } while (n == bfsize);
    return 0;
}


int on_udp_tunnel(struct eval *val, char *buffer, size_t bfsize)
{
    char *data = buffer;
    size_t data_len = bfsize;
    
    if (val->flag != FLAG_CONN) {
        data += S_SIZE_I6;
        data_len -= S_SIZE_I6;
    }
    struct sockaddr_ina addr = {0};
    
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
        ssize_t ns;
        
        if (val->flag == FLAG_CONN) {
            if (!val->in6.sin6_port) {
                if (!addr_equ(&addr, (struct sockaddr_ina *)&val->in6)) {
                    return 0;
                }
                if (connect(val->fd, &addr.sa, SA_SIZE(&addr)) < 0) {
                    uniperror("connect");
                    return -1;
                }
                val->in6 = addr.in6;
            }
            if (*(data + 2) != 0) { // frag
                continue;
            }
            int offs = s5_get_addr(data, n, &addr, SOCK_DGRAM);
            if (offs < 0) {
                LOG(LOG_E, "udp parse error\n");
                return -1;
            }
            if (!val->pair->in6.sin6_port) {
                if (params.baddr.sin6_family == AF_INET6) {
                    map_fix(&addr, 6);
                }
                if (params.baddr.sin6_family != addr.sa.sa_family) {
                    return -1;
                }
                if (socket_mod(val->pair->fd, &addr.sa) < 0) {
                    return -1;
                }
                if (connect(val->pair->fd, &addr.sa, SA_SIZE(&addr)) < 0) {
                    uniperror("connect");
                    return -1;
                }
                val->pair->in6 = addr.in6;
            }
            ns = udp_hook(val->pair, data + offs, bfsize - offs, n - offs, 
                (struct sockaddr_ina *)&val->pair->in6);
        }
        else {
            map_fix(&addr, 0);
            memset(buffer, 0, S_SIZE_I6);
            
            int offs = s5_set_addr(data, S_SIZE_I6, &addr, 1);
            if (offs < 0 || offs > S_SIZE_I6) {
                return -1;
            }
            ns = send(val->pair->pair->fd, data - offs, offs + n, 0);
        }
        if (ns < 0) {
            uniperror("sendto");
            return -1;
        }
    } while(1);
    return 0;
}


static inline int on_request(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize)
{
    struct sockaddr_ina dst = {0};
    
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        if (n) uniperror("ss recv");
        return -1;
    }
    int error = 0;
    
    if (*buffer == S_VER5) {
        if (val->flag != FLAG_S5) {
            if (auth_socks5(val->fd, buffer, n)) {
                return -1;
            }
            val->flag = FLAG_S5;
            return 0;
        }
        if (n < S_SIZE_MIN) {
            LOG(LOG_E, "ss: request to small (%zd)\n", n);
            return -1;
        }
        struct s5_req *r = (struct s5_req *)buffer;
        int s5e = 0;
        switch (r->cmd) {
            case S_CMD_CONN:
                s5e = s5_get_addr(buffer, n, &dst, SOCK_STREAM);
                if (s5e >= 0) {
                    error = connect_hook(pool, val, &dst, EV_CONNECT);
                }
                break;
            case S_CMD_AUDP:
                if (params.udp) {
                    s5e = s5_get_addr(buffer, n, &dst, SOCK_DGRAM);
                    if (s5e >= 0) {
                        error = udp_associate(pool, val, &dst);
                    }
                    break;
                }
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
    else if (*buffer == S_VER4) {
        val->flag = FLAG_S4;
        
        error = s4_get_addr(buffer, n, &dst);
        if (error) {
            if (resp_error(val->fd, error, FLAG_S4) < 0)
                uniperror("send");
            return -1;
        }
        error = connect_hook(pool, val, &dst, EV_CONNECT);
    }
    else {
        LOG(LOG_E, "ss: invalid version: 0x%x (%zd)\n", *buffer, n);
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


static inline int on_connect(struct poolhd *pool, struct eval *val, int e)
{
    int error = 0;
    socklen_t len = sizeof(error);
    if (e) {
        if (getsockopt(val->fd, SOL_SOCKET, 
                SO_ERROR, (char *)&error, &len)) {
            uniperror("getsockopt SO_ERROR");
            return -1;
        }
    }
    else {
        if (mod_etype(pool, val, POLLIN)) {
            uniperror("mod_etype");
            return -1;
        }
        val->type = EV_TUNNEL;
        val->pair->type = EV_DESYNC;
    }
    if (resp_error(val->pair->fd,
            error, val->pair->flag) < 0) {
        uniperror("send");
        return -1;
    }
    return e ? -1 : 0;
}


void close_conn(struct poolhd *pool, struct eval *val)
{
    LOG(LOG_S, "close: fds=%d,%d\n", val->fd, val->pair ? val->pair->fd : -1);
    del_event(pool, val);
}


int event_loop(int srvfd) 
{
    size_t bfsize = params.bfsize;
    
    struct poolhd *pool = init_pool(params.max_open * 2 + 1);
    if (!pool) {
        uniperror("init pool");
        close(srvfd);
        return -1;
    }
    if (!add_event(pool, EV_ACCEPT, srvfd, POLLIN)) {
        uniperror("add event");
        destroy_pool(pool);
        close(srvfd);
        return -1;
    }
    char *buffer = malloc(params.bfsize);
    if (!buffer) {
        uniperror("malloc");
        destroy_pool(pool);
        return -1;
    }
    
    struct eval *val;
    int i = -1, etype;
    
    while (NOT_EXIT) {
        val = next_event(pool, &i, &etype);
        if (!val) {
            if (get_e() == EINTR) 
                continue;
            uniperror("(e)poll");
            break;
        }
        assert(val->type >= 0
            && val->type < sizeof(eid_name)/sizeof(*eid_name));
        LOG(LOG_L, "new event: fd: %d, evt: %s, mod_iter: %d\n", val->fd, eid_name[val->type], val->mod_iter);
        
        switch (val->type) {
            case EV_ACCEPT:
                if ((etype & POLLHUP) ||
                        on_accept(pool, val))
                    NOT_EXIT = 0;
                continue;
            
            case EV_REQUEST:
                if ((etype & POLLHUP) || 
                        on_request(pool, val, buffer, bfsize))
                    close_conn(pool, val);
                continue;
        
            case EV_PRE_TUNNEL:
                if (on_tunnel_check(pool, val, 
                        buffer, bfsize, etype & POLLOUT))
                    close_conn(pool, val);
                continue;
                
            case EV_TUNNEL:
                if (on_tunnel(pool, val, buffer, bfsize, etype))
                    close_conn(pool, val);
                continue;
        
            case EV_UDP_TUNNEL:
                if (on_udp_tunnel(val, buffer, bfsize))
                    close_conn(pool, val);
                continue;
                
            case EV_CONNECT:
                if (on_connect(pool, val, etype & POLLERR))
                    close_conn(pool, val);
                continue;
                
            case EV_DESYNC:
                if (on_desync(pool, val, 
                        buffer, bfsize, etype & POLLOUT))
                    close_conn(pool, val);
                continue;
                    
            case EV_IGNORE:
                if (etype & (POLLHUP | POLLERR | POLLRDHUP))
                    close_conn(pool, val);
                continue;
            
            default:
                LOG(LOG_E, "???\n");
                NOT_EXIT = 0;
        }
    }
    LOG(LOG_S, "exit\n");
    free(buffer);
    destroy_pool(pool);
    return 0;
}


int listen_socket(struct sockaddr_ina *srv)
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


int run(struct sockaddr_ina *srv)
{
    #ifdef SIGPIPE
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        uniperror("signal SIGPIPE!");
    #endif
    signal(SIGINT, on_cancel);
    
    int fd = listen_socket(srv);
    if (fd < 0) {
        return -1;
    }
    return event_loop(fd);
}
    
