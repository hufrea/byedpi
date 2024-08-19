#include "extend.h"

#ifdef _WIN32
    #include <ws2tcpip.h>
    
    #ifndef TCP_MAXRT
    #define TCP_MAXRT 5
    #endif
#else
    #include <arpa/inet.h>
    #include <netinet/tcp.h>
    #include <sys/un.h>
    #include <sys/time.h>
#endif

#include <string.h>
#include <assert.h>

#include "proxy.h"
#include "error.h"
#include "params.h"

#include "desync.h"
#include "packets.h"


int set_timeout(int fd, unsigned int s)
{
    #ifdef __linux__
    if (setsockopt(fd, IPPROTO_TCP,
            TCP_USER_TIMEOUT, (char *)&s, sizeof(s))) {
        uniperror("setsockopt TCP_USER_TIMEOUT");
        return -1;
    }
    #else
    #ifdef _WIN32
    if (setsockopt(fd, IPPROTO_TCP,
            TCP_MAXRT, (char *)&s, sizeof(s))) {
        uniperror("setsockopt TCP_MAXRT");
        return -1;
    }
    #endif
    #endif
    return 0;
}


int mode_add_get(struct sockaddr_ina *dst, int m)
{
    // m < 0: get, m > 0: set, m == 0: delete
    assert(m >= -1 && m < params.dp_count);
    
    time_t t = 0;
    struct elem *val = 0;
    char *str = (char *)&dst->in;
    int len = 0;
    
    if (dst->sa.sa_family == AF_INET) {
        len = sizeof(dst->in);
    }
    else {
        len = sizeof(dst->in6) - sizeof(dst->in6.sin6_scope_id);
    }
    len -= sizeof(dst->sa.sa_family);
    assert(len > 0);
    
    if (m == 0) {
        mem_delete(params.mempool, str, len);
        return 0;
    }
    else if (m > 0) {
        time(&t);
        val = mem_add(params.mempool, str, len);
        if (!val) {
            uniperror("mem_add");
            return -1;
        }
        val->m = m;
        val->time = t;
        return 0;
    }
    val = mem_get(params.mempool, str, len);
    if (!val) {
        return -1;
    }
    time(&t);
    if (t > val->time + params.cache_ttl) {
        LOG(LOG_S, "time=%ld, now=%ld, ignore\n", val->time, t);
        return 0;
    }
    return val->m;
}


static inline bool check_port(uint16_t *p, struct sockaddr_in6 *dst)
{
    return (dst->sin6_port >= p[0] 
            && dst->sin6_port <= p[1]);
}


int connect_hook(struct poolhd *pool, struct eval *val, 
        struct sockaddr_ina *dst, int next)
{
    int m = mode_add_get(dst, -1);
    val->cache = (m == 0);
    val->attempt = m < 0 ? 0 : m;
    
    return create_conn(pool, val, dst, next);
}


int socket_mod(int fd, struct sockaddr *dst)
{
    if (params.custom_ttl) {
        if (setttl(fd, params.def_ttl, get_family(dst)) < 0) {
            return -1;
        }
    }
    if (params.protect_path) {
        return protect(fd, params.protect_path);
    }
    return 0;
}


int reconnect(struct poolhd *pool, struct eval *val, int m)
{
    struct eval *client = val->pair;
    
    if (create_conn(pool, client, 
            (struct sockaddr_ina *)&val->in6, EV_DESYNC)) {
        return -1;
    }
    val->pair = 0;
    del_event(pool, val);
    
    client->type = EV_IGNORE;
    client->attempt = m;
    client->cache = 1;
    client->buff.offset = 0;
    return 0;
}


bool check_host(struct mphdr *hosts, struct eval *val)
{
    char *host = 0;
    int len;
    if (!(len = parse_tls(val->buff.data, val->buff.size, &host))) {
        len = parse_http(val->buff.data, val->buff.size, &host, 0);
    }
    assert(len == 0 || host != 0);
    if (len <= 0) {
        return 0;
    }
    char *e = host + len;
    for (; host < e; host++) {
        if (mem_get(hosts, host, e - host)) {
            return 1;
        }
        if (!(host = memchr(host, '.', e - host))) {
            return 0;
        }
    }
    return 0;
}


bool check_proto_tcp(int proto, struct eval *val)
{
    if (proto & IS_TCP) {
        return 1;
    }
    else if ((proto & IS_HTTP) && 
            is_http(val->buff.data, val->buff.size)) {
        return 1;
    }
    else if ((proto & IS_HTTPS) && 
            is_tls_chello(val->buff.data, val->buff.size)) {
        return 1;
    }
    return 0;
}


int on_torst(struct poolhd *pool, struct eval *val)
{
    int m = val->pair->attempt + 1;
    
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect) {
            return -1;
        }
        if (dp->detect & DETECT_TORST) {
            break;
        }
    }
    if (m >= params.dp_count) {
        mode_add_get(
            (struct sockaddr_ina *)&val->in6, 0);
        return -1;
    }
    return reconnect(pool, val, m);
}


int on_fin(struct poolhd *pool, struct eval *val)
{
    int m = val->pair->attempt + 1;
    
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect) {
            return -1;
        }
        if (!(dp->detect & DETECT_TLS_ERR)) {
            continue;
        }
        char *req = val->pair->buff.data;
        ssize_t qn = val->pair->buff.size;

        if (!is_tls_chello(req, qn)) {
            continue;
        }
        return reconnect(pool, val, m);
    }
    return -1;
}


int on_response(struct poolhd *pool, struct eval *val, 
        char *resp, ssize_t sn)
{
    int m = val->pair->attempt + 1;
    
    char *req = val->pair->buff.data;
    ssize_t qn = val->pair->buff.size;
    
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect) {
            return -1;
        }
        if ((dp->detect & DETECT_HTTP_LOCAT)
                && is_http_redirect(req, qn, resp, sn)) {
            break;
        }
        else if ((dp->detect & DETECT_TLS_ERR)
                && ((is_tls_chello(req, qn) && !is_tls_shello(resp, sn))
                    || neq_tls_sid(req, qn, resp, sn))) {
            break;
        }
    }
    if (m < params.dp_count) {
        return reconnect(pool, val, m);
    }
    return -1;
}


static inline void to_tunnel(struct eval *client)
{
    client->pair->type = EV_TUNNEL;
    client->type = EV_TUNNEL;
    
    assert(client->buff.data);
    free(client->buff.data);
    client->buff.data = 0;
    client->buff.size = 0;
    client->buff.offset = 0;
}


int on_tunnel_check(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, int out)
{
    assert(!out);
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        if (n) uniperror("recv");
        switch (get_e()) {
            case ECONNRESET:
            case ECONNREFUSED:
            case ETIMEDOUT: 
                return on_torst(pool, val);
        }
        return on_fin(pool, val);
    }
    //
    if (on_response(pool, val, buffer, n) == 0) {
        return 0;
    }
    val->recv_count += n;
    struct eval *pair = val->pair;
    
    ssize_t sn = send(pair->fd, buffer, n, 0);
    if (n != sn) {
        uniperror("send");
        return -1;
    }
    to_tunnel(pair);
    
    if (params.timeout &&
            set_timeout(val->fd, 0)) {
        return -1;
    }
    int m = pair->attempt;
    
    if (post_desync(val->fd, m)) {
        return -1;
    }
    
    if (!pair->cache) {
        return 0;
    }
    struct sockaddr_ina *addr = (struct sockaddr_ina *)&val->in6;
    
    if (m == 0) {
        LOG(LOG_S, "delete ip: m=%d\n", m);
    } else {
        INIT_ADDR_STR((*addr));
        LOG(LOG_S, "save ip: %s, m=%d\n", ADDR_STR, m);
    }
    return mode_add_get(addr, m);
}


int on_desync_again(struct poolhd *pool,
        struct eval *val, char *buffer, size_t bfsize)
{
    if (val->flag == FLAG_CONN) {
        if (mod_etype(pool, val, POLLIN)) {
            uniperror("mod_etype");
            return -1;
        }
        val = val->pair;
    }
    int m = val->attempt;
    LOG((m ? LOG_S : LOG_L), "desync params index: %d\n", m);
    
    ssize_t n = val->buff.size;
    assert(n > 0 && n <= params.bfsize);
    memcpy(buffer, val->buff.data, n);
    
    if (params.timeout &&
            set_timeout(val->pair->fd, params.timeout)) {
        return -1;
    }
    ssize_t sn = desync(val->pair->fd, buffer, bfsize, n,
        val->buff.offset, (struct sockaddr *)&val->pair->in6, m);
    if (sn < 0) {
        return -1;
    }
    val->buff.offset += sn;
    if (sn < n) {
        if (mod_etype(pool, val->pair, POLLOUT)) {
            uniperror("mod_etype");
            return -1;
        }
        val->pair->type = EV_DESYNC;
        return 0;
    }
    val->pair->type = EV_PRE_TUNNEL;
    return 0;
}


int on_desync(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, int out)
{
    if (out) {
        return on_desync_again(pool, val, buffer, bfsize);
    }
    if (val->buff.size == bfsize) {
        to_tunnel(val);
        return 0;
    }
    ssize_t n = recv(val->fd, buffer, bfsize - val->buff.size, 0);
    if (n <= 0) {
        if (n) uniperror("recv data");
        return -1;
    }
    val->buff.size += n;
    val->recv_count += n;
    
    val->buff.data = realloc(val->buff.data, val->buff.size);
    if (val->buff.data == 0) {
        uniperror("realloc");
        return -1;
    }
    memcpy(val->buff.data + val->buff.size - n, buffer, n);
    
    int m = val->attempt;
    if (!m) for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect &&
                (!dp->pf[0] || check_port(dp->pf, &val->pair->in6)) &&
                (!dp->proto || check_proto_tcp(dp->proto, val)) &&
                (!dp->hosts || check_host(dp->hosts, val))) {
            break;
        }
    }
    if (m >= params.dp_count) {
        return -1;
    }
    val->attempt = m;
    
    return on_desync_again(pool, val, buffer, bfsize);
}


ssize_t udp_hook(struct eval *val, 
        char *buffer, size_t bfsize, ssize_t n, struct sockaddr_ina *dst)
{
    if (val->recv_count) {
        return send(val->fd, buffer, n, 0);
    }
    int m = val->attempt;
    if (!m) for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect && 
                (!dp->proto || (dp->proto & IS_UDP)) &&
                (!dp->pf[0] || check_port(dp->pf, &dst->in6))) {
            break;
        }
    }
    if (m >= params.dp_count) {
        return -1;
    }   
    return desync_udp(val->fd, buffer, bfsize, n, &dst->sa, m);
}


#ifdef __linux__
int protect(int conn_fd, const char *path)
{
    struct sockaddr_un sa;
    sa.sun_family = AF_UNIX;
    strcpy(sa.sun_path, path);
    
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        uniperror("socket");  
        return -1;
    }
    struct timeval tv = { .tv_sec = 1 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
    
    int err = connect(fd, (struct sockaddr *)&sa, sizeof(sa));
    if (err) {
        uniperror("connect");
        close(fd);
        return -1;
    }
    char buf[CMSG_SPACE(sizeof(fd))] = {};
    struct iovec io = { .iov_base = "1", .iov_len = 1 };
    struct msghdr msg = { .msg_iov = &io };
    
    msg.msg_iovlen = 1;
    msg.msg_control = buf;
    msg.msg_controllen = sizeof(buf);

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(conn_fd));

    *((int *)CMSG_DATA(cmsg)) = conn_fd;
    msg.msg_controllen = CMSG_SPACE(sizeof(conn_fd));

    if (sendmsg(fd, &msg, 0) < 0) {
        uniperror("sendmsg");
        close(fd);
        return -1;
    }
    if (recv(fd, buf, 1, 0) < 1) {
        uniperror("recv");
        close(fd);
        return -1;
    }
    close(fd);
    return 0;
}
#endif
