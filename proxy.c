#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>

#include <proxy.h>
#include <params.h>
#include <conev.h>
#include <desync.h>
#include <error.h>

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
        addr->in.sin_addr = *(struct in_addr *)(&ipv6m->o32);
    }
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
        struct sockaddr_ina *addr) 
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = SOCK_STREAM;
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
        if (resolve(id_end + 1, len, dst)) {
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


int s5_get_addr(char *buffer, ssize_t n,
        struct sockaddr_ina *addr) 
{
    struct s5_req *r = (struct s5_req *)buffer;
    
    int o = (r->atp == S_ATP_I4 ? S_SIZE_I4 : 
            (r->atp == S_ATP_ID ? r->id.len + S_SIZE_ID : 
            (r->atp == S_ATP_I6 ? S_SIZE_I6 : 0)));
    if (n < o)  {
        LOG(LOG_E, "ss: bad request\n");
        return S_ER_GEN;
    }
    if (r->cmd != S_CMD_CONN) {
        LOG(LOG_E, "ss: unsupported cmd: 0x%x\n", r->cmd);
        return S_ER_CMD;
    }
    switch (r->atp) {
        case S_ATP_I4:
            addr->in.sin_family = AF_INET;
            addr->in.sin_addr = r->i4;
            break;
        
        case S_ATP_ID:
            if (!params.resolve) {
                return S_ER_ATP;
            }
            if (r->id.len < 3 || 
                    resolve(r->id.domain, r->id.len, addr)) {
                LOG(LOG_E, "not resolved: %.*s\n", r->id.len, r->id.domain);
                return S_ER_HOST;
            }
            break;
        
        case S_ATP_I6:
            if (!params.ipv6)
                return S_ER_ATP;
            else {
                addr->in6.sin6_family = AF_INET6;
                addr->in6.sin6_addr = r->i6;
            }
    }
    addr->in.sin_port = *(uint16_t *)&buffer[o - 2];
    return 0;
}


int create_conn(struct poolhd *pool,
        struct eval *val, struct sockaddr_ina *dst)
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
            sizeof(params.baddr)) < 0) {
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
    #endif
    int one = 1;
    if (setsockopt(sfd, IPPROTO_TCP,
            TCP_NODELAY, (char *)&one, sizeof(one))) {
        uniperror("setsockopt TCP_NODELAY");
        close(sfd);
        return -1;
    }
    int status = connect(sfd, &addr.sa, sizeof(addr));
    if (status < 0 && 
            get_e() != EINPROGRESS && get_e() != EAGAIN) {
        uniperror("connect");
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


static inline int on_request(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize)
{
    struct sockaddr_ina dst = {0};
    
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        if (n) uniperror("ss recv");
        return -1;
    }
    if (*buffer == S_VER5) {
        if (val->flag != FLAG_S5) {
            if (auth_socks5(val->fd, buffer, n)) {
                return -1;
            }
            val->flag = FLAG_S5;
            return 0;
        }
        if (n < S_SIZE_MIN) {
            LOG(LOG_E, "ss: request to small\n");
            return -1;
        }
        int s5e = s5_get_addr(buffer, n, &dst);
        if (!s5e &&
                create_conn(pool, val, &dst)) {
            s5e = S_ER_GEN;
        }
        if (s5e) {
            resp_s5_error(val->fd, s5e);
            return -1;
        }
    }
    else if (*buffer == S_VER4) {
        val->flag = FLAG_S4;
        
        int error = s4_get_addr(buffer, n, &dst);
        if (!error) {
            error = create_conn(pool, val, &dst);
        }
        if (error) {
            if (resp_error(val->fd, error, FLAG_S4) < 0)
                uniperror("send");
            return -1;
        }
    }
    else {
        LOG(LOG_E, "ss: invalid version: 0x%x (%lu)\n", *buffer, n);
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
            if (get_e() == EAGAIN ||
                    get_e() == EINPROGRESS)
                break;
            uniperror("accept");
            return -1;
        }
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
        if (!(rval = add_event(pool, EV_REQUEST, c, 0))) {
            close(c);
            continue;
        }
        rval->in6 = client.in6;
    }
    return 0;
}


static inline int on_connect(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, int e)
{
    if (val->flag == FLAG_CONN) {
        int error = 0;
        socklen_t len = sizeof(error);
        if (e) {
            if (getsockopt(val->fd, SOL_SOCKET, 
                    SO_ERROR, (char *)&error, &len)) {
                uniperror("getsockopt SO_ERROR");
                return -1;
            }
        }
        if (resp_error(val->pair->fd,
                error, val->pair->flag) < 0) {
            uniperror("send");
            return -1;
        }
        if (e) {
            return -1;
        }
        if (mod_etype(pool, val, POLLOUT, 0)) {
            uniperror("mod_etype");
            return -1;
        }
        val->type = EV_TUNNEL;
        val->pair->type = EV_CONNECT;
    }
    else {
        ssize_t n = recv(val->fd, buffer, bfsize, 0);
        if (n <= 0) {
            if (n) uniperror("recv data");
            return -1;
        }
        if (desync(val->pair->fd, buffer, bfsize,
                n, (struct sockaddr *)&val->pair->in6)) {
            return -1;
        }
        val->type = EV_TUNNEL;
    }
    return 0;
}


static inline int on_tunnel(struct poolhd *pool, struct eval *val, 
        char *buffer, size_t bfsize, int out)
{
    ssize_t n = 0;
    struct eval *pair = val->pair;
    
    if (pair->tmpbuf && out) {
        pair = val;
        val = val->pair;
        
        n = val->size - val->offset;
        ssize_t sn = send(pair->fd, val->tmpbuf + val->offset, n, 0);
        if (sn != n) {
            if (sn < 0 && get_e() != EAGAIN) {
                uniperror("send");
                return -1;
            }
            if (sn > 0)
                val->offset += sn;
            return 0;
        }
        free(val->tmpbuf);
        val->tmpbuf = 0;
        
        if (mod_etype(pool, val, POLLIN, 1) ||
                mod_etype(pool, pair, POLLOUT, 0)) {
            uniperror("mod_etype");
            return -1;
        }
    }
    do {
        n = recv(val->fd, buffer, bfsize, 0);
        if (n < 0 && get_e() == EAGAIN)
            break;
        if (n < 1) {
            if (n) uniperror("recv");
            return -1;
        }
        ssize_t sn = send(pair->fd, buffer, n, 0);
        if (sn != n) {
            if (sn < 0) {
                if (get_e() != EAGAIN) {
                    uniperror("send");
                    return -1;
                }
                sn = 0;
            }
            LOG(LOG_S, "EAGAIN, set POLLOUT (fd: %d)\n", pair->fd);
            
            val->size = n - sn;
            if (!(val->tmpbuf = malloc(val->size))) {
                perror("malloc");
                return -1;
            }
            memcpy(val->tmpbuf, buffer + sn, val->size);
            
            if (mod_etype(pool, val, POLLIN, 0) ||
                    mod_etype(pool, pair, POLLOUT, 1)) {
                uniperror("mod_etype");
                return -1;
            }
            break;
        }
    } while (n == bfsize);
    return 0;
}


int big_loop(int srvfd) 
{
    size_t bfsize = params.bfsize;
    
    struct poolhd *pool = init_pool(params.max_open * 2 + 1);
    if (!pool) {
        perror("init pool");
        close(srvfd);
        return -1;
    }
    if (!add_event(pool, EV_ACCEPT, srvfd, 0)) {
        perror("add event");
        destroy_pool(pool);
        close(srvfd);
        return -1;
    }
    char *buffer = malloc(params.bfsize);
    if (!buffer) {
        perror("malloc");
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
                
            case EV_IGNORE:
                if (etype & (POLLHUP | POLLERR | POLLRDHUP))
                    del_event(pool, val);
                continue;
            
            default:
                LOG(LOG_E, "???\n");
                NOT_EXIT = 0;
        }
    }
    LOG(LOG_E, "exit\n");
    free(buffer);
    destroy_pool(pool);
    return 0;
}


int listener(struct sockaddr_ina srv)
{
    #ifdef SIGPIPE
    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR)
        uniperror("signal SIGPIPE!");
    #endif
    signal(SIGINT, on_cancel);
    
    int srvfd = nb_socket(srv.sa.sa_family, SOCK_STREAM);
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
    if (bind(srvfd, &srv.sa, sizeof(srv)) < 0) {
        uniperror("bind");  
        close(srvfd);
        return -1;
    }
    if (listen(srvfd, 10)) {
        uniperror("listen");
        close(srvfd);
        return -1;
    }
    return big_loop(srvfd);
}
