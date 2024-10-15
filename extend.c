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

#define KEY_SIZE sizeof(struct sockaddr_ina)


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


static ssize_t serialize_addr(const struct sockaddr_ina *dst,
        uint8_t *const out, const size_t out_len)
{
    #define serialize(raw, field, len, counter){ \
        const size_t size = sizeof(field); \
        if ((counter + size) <= len) { \
            memcpy(raw + counter, &(field), size); \
            counter += size; \
        } else return 0; \
    }
    size_t c = 0;
    serialize(out, dst->in.sin_port, out_len, c);
    serialize(out, dst->sa.sa_family, out_len, c);
    
    if (dst->sa.sa_family == AF_INET) {
        serialize(out, dst->in.sin_addr, out_len, c);
    } else {
        serialize(out, dst->in6.sin6_addr, out_len, c);
    }
    #undef serialize

    return c;
}


static int mode_add_get(struct sockaddr_ina *dst, int m)
{
    // m < 0: get, m > 0: set, m == 0: delete
    assert(m >= -1 && m < params.dp_count);
    
    time_t t = 0;
    struct elem *val = 0;
    
    uint8_t key[KEY_SIZE] = { 0 };
    int len = serialize_addr(dst, key, sizeof(key));
    assert(len > 0);
    
    if (m < 0) {
        val = mem_get(params.mempool, (char *)key, len);
        if (!val) {
            return -1;
        }
        time(&t);
        if (t > val->time + params.cache_ttl) {
            LOG(LOG_S, "time=%jd, now=%jd, ignore\n", (intmax_t)val->time, (intmax_t)t);
            return 0;
        }
        return val->m;
    }
    INIT_ADDR_STR((*dst));

    if (m == 0) {
        LOG(LOG_S, "delete ip: %s\n", ADDR_STR);
        mem_delete(params.mempool, (char *)key, len);
        return 0;
    }
    else {
        LOG(LOG_S, "save ip: %s, m=%d\n", ADDR_STR, m);
        time(&t);

        val = mem_add(params.mempool, (char *)key, len);
        if (!val) {
            uniperror("mem_add");
            return -1;
        }
        val->m = m;
        val->time = t;
        return 0;
    }
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
        if (setttl(fd, params.def_ttl) < 0) {
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
    assert(val->flag == FLAG_CONN);
    
    struct eval *client = val->pair;
    
    if (create_conn(pool, client, 
            (struct sockaddr_ina *)&val->in6, EV_TUNNEL)) {
        return -1;
    }
    val->pair = 0;
    del_event(pool, val);
    
    //client->type = EV_IGNORE;
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
    
    bool can_reconn = (
        val->pair->buff.data && !val->recv_count
    );
    if (can_reconn || params.auto_level > AUTO_NOSAVE) {
        for (; m < params.dp_count; m++) {
            struct desync_params *dp = &params.dp[m];
            if (!dp->detect) {
                m = 0;
                break;
            }
            if (dp->detect & DETECT_TORST) {
                break;
            }
        }
        if (m == 0) {
        }
        else if (m >= params.dp_count) {
            if (m > 1) mode_add_get(
                (struct sockaddr_ina *)&val->in6, 0);
        }
        else if (can_reconn) {
            return reconnect(pool, val, m);
        }
        else mode_add_get(
            (struct sockaddr_ina *)&val->in6, m);
    }
    struct linger l = { .l_onoff = 1 };
    if (setsockopt(val->pair->fd, SOL_SOCKET,
            SO_LINGER, (char *)&l, sizeof(l)) < 0) {
        uniperror("setsockopt SO_LINGER");
        return -1;
    }
    return -1;
}


int on_fin(struct poolhd *pool, struct eval *val)
{
    int m = val->pair->attempt + 1;
    
    bool can_reconn = (
        val->pair->buff.data && !val->recv_count
    );
    if (!can_reconn && params.auto_level <= AUTO_NOSAVE) {
        return -1;
    }
    bool ssl_err = 0;
    
    if (can_reconn) {
        char *req = val->pair->buff.data;
        ssize_t qn = val->pair->buff.size;
    
        ssl_err = is_tls_chello(req, qn);
    }
    else if (val->pair->mark && val->round_count <= 1) {
        ssl_err = 1;
    }
    if (!ssl_err) {
        return -1;
    }
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect) {
            return -1;
        }
        if (dp->detect & DETECT_TLS_ERR) {
            if (can_reconn)
                return reconnect(pool, val, m);
            else {
                mode_add_get(
                    (struct sockaddr_ina *)&val->in6, m);
                return -1;
            }
        }
    }
    if (m > 1) { // delete
        mode_add_get(
            (struct sockaddr_ina *)&val->in6, 0);
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


static inline void free_first_req(struct eval *client)
{
    assert(client->buff.data);
    free(client->buff.data);
    memset(&client->buff, 0, sizeof(client->buff));
}


ssize_t on_first_send(struct eval *client, char *buffer, ssize_t n, ssize_t bfsize)
{
    int m = client->attempt;
    
    if (!m) for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect &&
                (!dp->pf[0] || check_port(dp->pf, &client->pair->in6)) &&
                (!dp->proto || check_proto_tcp(dp->proto, client)) &&
                (!dp->hosts || check_host(dp->hosts, client))) {
            break;
        }
    }
    if (m >= params.dp_count) {
        return -1;
    }
    if (params.auto_level > AUTO_NOSAVE && params.dp_count > 1) {
        client->mark = is_tls_chello(buffer, n);
    }
    client->attempt = m;
    
    if (params.timeout 
            && set_timeout(client->pair->fd, params.timeout)) {
        return -1;
    }
    if (client->buff.locked) {
        assert(bfsize >= client->buff.size);
        memcpy(buffer, client->buff.data, client->buff.size);
        return client->buff.size;
    }
    return n;
}


ssize_t tcp_send_hook(struct poolhd *pool, struct eval *remote,
        char *buffer, size_t bfsize, ssize_t n)
{
    ssize_t sn = -1;
    
    if (remote->flag != FLAG_CONN 
            || remote->pair->round_count > params.repeats) {
        sn = send(remote->fd, buffer, n, 0);
        if (sn < 0 && get_e() == EAGAIN) {
            return 0;
        }
        return sn;
    }
    struct eval *client = remote->pair;
    int m = client->attempt;
    
    if (client->recv_count == n) {
        n = on_first_send(client, buffer, n, bfsize);
        if (n < 0) {
            return -1;
        }
    }
    LOG((m ? LOG_S : LOG_L), "desync params index: %d\n", m);
    
    sn = desync(remote->fd, buffer, bfsize, n,
        0, (struct sockaddr *)&remote->in6, m);
    return sn;
}


ssize_t tcp_recv_hook(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize)
{
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        if (!n) {
            if (val->flag != FLAG_CONN) {
                val = val->pair;
            }
            return on_fin(pool, val);
        }
        if (get_e() == EAGAIN) {
            return 0;
        }
        uniperror("recv");
        switch (get_e()) {
            case ECONNRESET:
            case ECONNREFUSED:
            case ETIMEDOUT: 
                if (val->flag == FLAG_CONN)
                    return on_torst(pool, val);
                else
                    return on_fin(pool, val->pair);
        }
        return -1;
    }
    
    if (val->flag != FLAG_CONN 
            && params.auto_level > AUTO_NOBUFF 
            && val->pair->recv_count == 0) 
    {
        val->buff.size += n;
        
        if (val->buff.size >= bfsize) {
            free_first_req(val);
            return n;
        }
        val->buff.locked = 1;
        val->buff.data = realloc(val->buff.data, val->buff.size);
        
        if (val->buff.data == 0) {
            uniperror("realloc");
            return -1;
        }
        memcpy(val->buff.data + val->buff.size - n, buffer, n);
    }
    else if (val->recv_count == 0 && val->flag == FLAG_CONN)
    {
        if (val->pair->buff.locked) {
            if (on_response(pool, val, buffer, n) == 0) {
                return 0;
            }
            free_first_req(val->pair);
        }
        if (params.timeout && params.auto_level <= AUTO_NOSAVE &&
                set_timeout(val->fd, 0)) {
            return -1;
        }
        int m = val->pair->attempt;
        
        if (post_desync(val->fd, m)) {
            return -1;
        }
        if (val->pair->cache && 
                mode_add_get((struct sockaddr_ina *)&val->in6, m) < 0) {
            return -1;
        }
    }
    return n;
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
