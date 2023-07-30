#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include <proxy.h>
#include <packets.h>
#include <params.h>
#include <conev.h>
#include <desync.h>

int NOT_EXIT = 1;

static void on_cancel(int sig) {
    NOT_EXIT = 0;
}


static inline int ip_cmp(
        struct sockaddr_ina *a, struct sockaddr_ina *b)
{
    if (a->sa.sa_family == AF_INET) {
        return 
            *((uint32_t *)(&a->in.sin_addr)) !=
            *((uint32_t *)(&b->in.sin_addr));
    }
    return 
        *((uint64_t *)(&a->in6.sin6_addr)) !=
        *((uint64_t *)(&b->in6.sin6_addr)) || 
        *((uint64_t *)(&a->in6.sin6_addr) + 1) !=
        *((uint64_t *)(&b->in6.sin6_addr) + 1);
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
    else if ((ipv6m->o64 | ipv6m->o16) == 0 && 
            ipv6m->t16 == 0xffff && !f6) {
        addr->sa.sa_family = AF_INET;
        addr->in.sin_addr = *(struct in_addr *)(&ipv6m->o32);
    }
}


static inline int nb_socket(int domain, int type) {
    #ifdef __linux__
    int fd = socket(domain, type | SOCK_NONBLOCK, 0);
    #else
    int fd = socket(domain, type, 0);
    #endif
    if (fd < 0) {
        perror("socket");  
        return -1;
    }
    #ifndef __linux__
    if (fcntl(fd, F_SETFL, O_NONBLOCK) < 0) {
        perror("fcntl");
        close(fd);
        return -1;
    }
    #endif
    return fd;
}


int resolve(char *host, int len, 
        struct sockaddr_ina *addr, int type) 
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = type;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;
    
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
    buffer[1] = S_AUTH_BAD;
    long i = 2;
    for (; i < n; i++)
        if (buffer[i] == S_AUTH_NONE) {
            buffer[1] = S_AUTH_NONE;
            break;
        }
    if (send(fd, buffer, 2, 0) < 0) {
        perror("send");
        return -1;
    }
    return i < n ? 0 : -1;
}


int resp_error(int fd, int e, int flag, int re)
{
    if (flag & FLAG_S4) {
        struct s4_req s4r = { 
            .cmd = e ? S4_ER : S4_OK
        };
        return send(fd, &s4r, sizeof(s4r), 0);
    }
    else if (flag & FLAG_S5) {
        uint8_t se;
        if (re) se = (uint8_t )re;
        else switch (e) {
            case 0: se = S_ER_OK;
                break;
            case ECONNREFUSED: 
                se = S_ER_CONN;
                break;
            case EHOSTUNREACH:
            case ETIMEDOUT: 
                se = S_ER_HOST;
                break;
            case ENETUNREACH: 
                se = S_ER_NET;
                break;
            default: se = S_ER_GEN;
        }
        struct s5_rep s5r = { 
            .ver = 0x05, .code = se, 
            .atp = S_ATP_I4
        };
        return send(fd, &s5r, sizeof(s5r), 0);
    }
    return 0;
}


int handle_socks4(int fd, char *bf,
        size_t n, struct sockaddr_ina *dst)
{
    if (n < sizeof(struct s4_req) + 1) {
        return -1;
    }
    struct s4_req *r = (struct s4_req *)bf;
    char er = 0;
    
    if (r->cmd != S_CMD_CONN) {
        er = 1;
    }
    else if (ntohl(r->i4.s_addr) <= 255) do {
        er = 1;
        if (!params.resolve || bf[n - 1])
            break;
        char *ie = strchr(bf + sizeof(*r), 0);
        if (!ie)
            break;
        int len = (bf + n - ie) - 2;
        if (len < 3)
            break;
        if (resolve(ie + 1, len, dst, SOCK_STREAM)) {
            fprintf(stderr, "not resolved: %.*s\n", len, ie + 1);
            break;
        }
        er = 0;
    } while (0);
    else {
        dst->in.sin_family = AF_INET;
        dst->in.sin_addr = r->i4;
    }
    if (er) {
        if (resp_error(fd, 1, FLAG_S4, 0) < 0)
            perror("send");
        return -1;
    }
    dst->in.sin_port = r->port;
    return 0;
}


int s_get_addr(char *buffer, ssize_t n, 
        struct sockaddr_ina *addr, int type) 
{
    struct s5_req *r = (struct s5_req *)buffer;
    
    int o = (r->atp == S_ATP_I4 ? S_SIZE_I4 : 
            (r->atp == S_ATP_ID ? r->id.len + S_SIZE_ID : 
            (r->atp == S_ATP_I6 ? S_SIZE_I6 : 0)));
    if (n < o)  {
        fprintf(stderr, "ss: bad request\n");
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
            if (r->id.len == 1) {
                addr->in.sin_family = AF_INET;
                LOG(LOG_S, "domain len=1\n");
            }
            else if (resolve(r->id.domain, r->id.len, addr, type)) {
                fprintf(stderr, "not resolved: %.*s\n", r->id.len, r->id.domain);
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
    addr->in.sin_port = *(uint16_t *)&buffer[o - 2];
    return o;
}


int s_set_addr(char *buffer, ssize_t n,
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
}


int create_conn(struct poolhd *pool,
        struct eval *val, struct sockaddr_ina *dst)
{
    int sfd = nb_socket(dst->sa.sa_family, SOCK_STREAM);
    if (sfd < 0) {
        perror("socket");  
        return -1;
    }
    #ifdef __linux__
    int syn_count = 1;
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_SYNCNT, &syn_count, sizeof(syn_count))) {
        perror("setsockopt TCP_SYNCNT");
        close(sfd);
        return -1;
    }
    #endif
    int one = 1;
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_NODELAY, (char *)&one, sizeof(one))) {
        perror("setsockopt TCP_NODELAY");
        close(sfd);
        return -1;
    }
    if (setsockopt(sfd, SOL_SOCKET, SO_SNDBUF, 
            &params.send_bfsz, sizeof(params.send_bfsz)) < 0) {
        close(sfd);
        perror("setsockopt SO_SNDBUF");
        return -1;
    }
    int status = connect(sfd, &dst->sa, sizeof(*dst));
    if (status < 0 && errno != EINPROGRESS) {
        perror("connect");
        close(sfd);
        return -1;
    }
    struct eval *pair = add_event(pool, EV_CONNECT, sfd, POLLOUT);
    if (!pair) {
        close(sfd);
        return -1;
    }
    val->pair = pair;
    pair->pair = val;
    pair->in6 = dst->in6;
    pair->flag = FLAG_CONN;
    return 0;
}


int udp_asc(struct poolhd *pool, 
        struct eval *val, struct sockaddr_ina *dst)
{
    int ufd = nb_socket(AF_INET6, SOCK_DGRAM);
    if (ufd < 0) {
        perror("socket");  
        return -1;
    }
    struct sockaddr_ina addr = {0};
    socklen_t asz = sizeof(addr);
    int ip_is_set = ip_cmp(dst, &addr);
    
    addr.sa.sa_family = AF_INET6;
    if (bind(ufd, &addr.sa, sizeof(addr)) < 0) {
        perror("bind");  
        close(ufd);
        return -1;
    }
    if (getsockname(ufd, &addr.sa, &asz)) {
        perror("getsockname");
        close(ufd);
        return -1;
    }
    struct eval *upair = add_event(pool, EV_UDP_TUNNEL, ufd, POLLIN);
    if (!upair) {
        close(ufd);
        return -1;
    }
    upair->in6 = dst->in6;
    if (!ip_is_set) {
        if (dst->sa.sa_family == AF_INET)
            upair->in.sin_addr = val->in.sin_addr;
        else
            upair->in6.sin6_addr = val->in6.sin6_addr;
    }
    map_fix((struct sockaddr_ina *)&upair->in6, 6);
    val->pair = upair;
    upair->pair = val;
    
    struct s5_req s5r = { 
        .ver = 0x05 
    };
    int offs = s_set_addr((char *)&s5r, sizeof(s5r), &addr, 0);
    if (offs < 0) {
        return -1;
    }
    if (send(val->fd, &s5r, offs, 0) < 0) {
        perror("send");
        return -1;
    }
    return 0;
}


static inline int on_request(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize)
{
    struct sockaddr_ina dst = {0};
    int s = 0, ss_e = 0;
    
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        if (n) perror("ss recv");
        return -1;
    }
    if (*buffer == S_VER5) {
        if (val->flag != FLAG_S5) {
            if (auth_socks5(val->fd, buffer, n)) {
                return -1;
            }
            val->flag |= FLAG_S5;
            return 0;
        }
        if (n < S_SIZE_MIN) {
            fprintf(stderr, "ss: request to small\n");
            return -1;
        }
        struct s5_req *r = (struct s5_req *)buffer;
        
        ss_e = s_get_addr(buffer, n, &dst, SOCK_STREAM);
        if (ss_e > 0) switch (r->cmd) {
            case S_CMD_CONN:
                s = create_conn(pool, val, &dst);
                break;
            case S_CMD_AUDP:
                if (params.udp) {
                    s = udp_asc(pool, val, &dst);
                    break;
                }
            default:
                fprintf(stderr, "ss: unsupported cmd: 0x%x\n", r->cmd);
                ss_e = -S_ER_CMD;
        }
    }
    else if (*buffer == S_VER4) {
        if (handle_socks4(val->fd, buffer, n, &dst)) {
            return -1;
        }
        s = create_conn(pool, val, &dst);
        val->flag |= FLAG_S4;
    }
    else {
        fprintf(stderr, "ss: invalid version: 0x%x (%lu)\n", *buffer, n);
        return -1;
    }
    if (s || ss_e < 0) {
        if (resp_error(val->fd, errno, val->flag, -ss_e) < 0)
            perror("send");
        return -1;
    }
    val->type = EV_IGNORE;
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
            if (errno == EAGAIN) 
                break;
            perror("accept");
            return -1;
        }
        #ifndef __linux__
        if (fcntl(c, F_SETFL, O_NONBLOCK) < 0) {
            perror("fcntl");
            close(c);
            continue;
        }
        #endif
        int one = 1;
        if (setsockopt(c, IPPROTO_TCP,
                TCP_NODELAY, (char *)&one, sizeof(one))) {
            perror("setsockopt TCP_NODELAY");
            close(c);
            continue;
        }
        if (setsockopt(c, SOL_SOCKET, SO_SNDBUF, 
                &params.send_bfsz, sizeof(params.send_bfsz)) < 0) {
            perror("setsockopt SO_SNDBUF");
            close(c);
            continue;
        }
        if (!(rval = add_event(pool, EV_REQUEST, c, 0))) {
            close(c);
            continue;
        }
        rval->in6 = client.in6;
    }
    return 0;
}


static inline int on_data(struct eval *val, char *buffer, size_t bfsize)
{
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n <= 0) {
        if (n) perror("recv data");
        return -1;
    }
    if (desync(val->pair->fd, buffer, 
            n, (struct sockaddr *)&val->pair->in6)) {
        return -1;
    }
    val->type = EV_TUNNEL;
    return 0;
}


static inline int on_connect(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, int e)
{
    if (val->flag & FLAG_CONN) {
        int error = 0;
        socklen_t len = sizeof(error);
        if (e) {
            if (getsockopt(val->fd, SOL_SOCKET, 
                    SO_ERROR, (char *)&error, &len)) {
                perror("getsockopt SO_ERROR");
                return -1;
            }
        }
        if (resp_error(val->pair->fd,
                error, val->pair->flag, 0) < 0) {
            perror("send");
            return -1;
        }
        if (e) {
            return -1;
        }
        val->type = EV_TUNNEL;
        mod_etype(pool, val, POLLOUT, 0);
        val->pair->type = EV_CONNECT;
        return 0;
    }
    return on_data(val, buffer, bfsize);
}


static inline int on_tunnel(struct poolhd *pool, struct eval *val, 
        char *buffer, size_t bfsize, int out)
{
    ssize_t n = 0;
    char *rb = buffer;
    struct eval *pair = val->pair;
    
    if (pair->tmpbuf && out) {
        mod_etype(pool, val, POLLOUT, 0);
        mod_etype(pool, val->pair, POLLIN, 1);
        
        pair = val;
        val = val->pair;
    }
    do {
        if (val->tmpbuf) {
            n = val->size - val->offset;
            rb = val->tmpbuf + val->offset;
        } else {
            n = recv(val->fd, buffer, bfsize, 0);
            if (n < 0 && errno == EAGAIN)
                break;
            if (n < 1) {
                if (n) perror("recv server");
                return -1;
            }
        }
        ssize_t sn = send(pair->fd, rb, n, 0);
        if (sn != n) {
            if (sn < 0 && errno != EAGAIN) {
                perror("send");
                return -1;
            } else if (sn < 0) {
                sn = 0;
            }
            LOG(LOG_S, "EAGAIN, set POLLOUT (fd: %d)\n", pair->fd);
            mod_etype(pool, val, POLLIN, 0);
            mod_etype(pool, pair, POLLOUT, 1);
            
            if (val->tmpbuf) {
                LOG(LOG_S, "EAGAIN, AGAIN ! (fd: %d)\n", pair->fd);
                if (sn > 0)
                    val->offset += sn;
                break;
            }
            val->size = n - sn;
            if (!(val->tmpbuf = malloc(val->size))) {
                perror("malloc");
                return -1;
            }
            memcpy(val->tmpbuf, buffer + sn, val->size);
            break;
        }
        else if (val->tmpbuf) {
            free(val->tmpbuf);
            val->tmpbuf = 0;
            rb = buffer;
            continue;
        }
    } while (n == bfsize);
    return 0;
}


int on_udp_tunnel(struct eval *val, char *buffer, size_t bfsize)
{
    struct sockaddr_ina addr;
    int skip = S_SIZE_I6, offs;
    do {
        socklen_t asz = sizeof(addr);
        ssize_t n = recvfrom(val->fd, buffer + skip,
            bfsize - skip, 0, &addr.sa, &asz), ns;
            
        if (n < 0 && errno == EAGAIN)
            break;
        if (n < 1) {
            perror("recv udp");
            return -1;
        }
        
        if (!val->in6.sin6_port) {
            val->in6.sin6_port = addr.in6.sin6_port;
        }
        if (!ip_cmp((struct sockaddr_ina *)&val->in6, &addr) &&
                    addr.in6.sin6_port == val->in6.sin6_port) {
            if (buffer[skip + 2]) { // frag
                continue;
            }
            offs = s_get_addr(buffer + skip, n, &addr, SOCK_DGRAM);
            if (offs < 0) {
                return -1;
            }
            map_fix(&addr, 6);
            
            if ((val->flag & FLAG_CONN))
                ns = sendto(val->fd,
                    buffer + skip + offs, n - offs, 0, &addr.sa, asz);
            else {
                ns = desync_udp(val->fd, 
                    buffer + skip + offs, n - offs, &addr.sa);
                val->flag |= FLAG_CONN;
            }
        } else {
            map_fix(&addr, 0);
            
            offs = s_set_addr(buffer + skip, skip, &addr, 1);
            if (offs < 0 || offs > skip) {
                return -1;
            }
            ns = sendto(val->fd, buffer + skip - offs,
                n + offs, 0, (struct sockaddr *)&val->in6, sizeof(val->in6));
        }
        if (ns < 0) {
            perror("sendto");
            return -1;
        }
    } while(1);
    return 0;
}


int big_loop(int srvfd) 
{
    size_t bfsize = params.bfsize;
    
    struct poolhd *pool = init_pool(params.max_open * 2 + 1);
    if (!pool) {
        perror("init pool");
        return -1;
    }
    char *buffer = malloc(params.bfsize);
    if (!buffer) {
        perror("malloc");
        return -1;
    }
    add_event(pool, EV_ACCEPT, srvfd, 0);
    
    struct eval *val;
    int i = -1, etype;
    
    while (NOT_EXIT) {
        val = next_event(pool, &i, &etype);
        if (!val) {
            if (errno == EINTR) 
                continue;
            perror("(e)poll");
            break;
        }
        LOG(LOG_L, "new event: fd: %d, evt: %s\n", val->fd, eid_name[val->type]);
            
        if (!val->fd) {
            continue;
        }
        switch (val->type) {
            case EV_ACCEPT:
                if (on_accept(pool, val))
                    NOT_EXIT = 0;
                continue;
            
            case EV_REQUEST:
                if ((etype & POLLHUP) || 
                        on_request(pool, val, buffer, bfsize))
                    del_event(pool, val);
                continue;
        
            case EV_TUNNEL:
                if (on_tunnel(pool, val, buffer, bfsize, etype & POLLOUT))
                    del_event(pool, val);
                continue;
        
            case EV_CONNECT:
                if (on_connect(pool, val, buffer, bfsize, etype & POLLERR))
                    del_event(pool, val);
                continue;
                
            case EV_UDP_TUNNEL:
                if (on_udp_tunnel(val, buffer, bfsize))
                    del_event(pool, val);
                continue;
                
            case EV_IGNORE:
                if (etype & (POLLHUP | POLLERR | POLLRDHUP))
                    del_event(pool, val);
                continue;
            
            default:
                fprintf(stderr, "???\n");
                NOT_EXIT = 0;
        }
    }
    fprintf(stderr, "exit\n");
    free(buffer);
    destroy_pool(pool);
    return 0;
}


int listener(struct sockaddr_ina srv)
{
    if (signal(SIGPIPE, SIG_IGN))
        perror("signal SIGPIPE!");
        
    if (signal(SIGINT, on_cancel))
        perror("signal SIGINT!");
    
    int srvfd = nb_socket(srv.sa.sa_family, SOCK_STREAM);
    if (srvfd < 0) {
        perror("socket");  
        return -1;  
    }
    int opt = 1;
    if (setsockopt(srvfd, SOL_SOCKET, 
            SO_REUSEADDR, (char *)&opt, sizeof(opt)) == -1) {
        perror("setsockopt");
        close(srvfd);
        return -1;
    }
    if (bind(srvfd, &srv.sa, sizeof(srv)) < 0) {
        perror("bind");  
        close(srvfd);
        return -1;
    }
    if (listen(srvfd, 10)) {
        perror("listen");
        close(srvfd);
        return -1;
    }
    int status = big_loop(srvfd);
    close(srvfd);
    return status;
}