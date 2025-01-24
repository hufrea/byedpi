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

#define KEY_SIZE sizeof(union sockaddr_u)


static int set_timeout(int fd, unsigned int s)
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


static ssize_t serialize_addr(const union sockaddr_u *dst,
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


static int cache_get(const union sockaddr_u *dst)
{
    uint8_t key[KEY_SIZE] = { 0 };
    int len = serialize_addr(dst, key, sizeof(key));
    
    struct elem_i *val = (struct elem_i *)mem_get(params.mempool, (char *)key, len);
    if (!val) {
        return -1;
    }
    time_t t = time(0);
    if (t > val->time + params.cache_ttl) {
        LOG(LOG_S, "time=%jd, now=%jd, ignore\n", (intmax_t)val->time, (intmax_t)t);
        return 0;
    }
    return val->m;
}


static int cache_add(const union sockaddr_u *dst, int m)
{
    assert(m >= 0 && m < params.dp_count);
    
    uint8_t key[KEY_SIZE] = { 0 };
    int len = serialize_addr(dst, key, sizeof(key));
    
    INIT_ADDR_STR((*dst));
    if (m == 0) {
        LOG(LOG_S, "delete ip: %s\n", ADDR_STR);
        mem_delete(params.mempool, (char *)key, len);
        return 0;
    }
    LOG(LOG_S, "save ip: %s, m=%d\n", ADDR_STR, m);
    time_t t = time(0);
    
    char *key_d = malloc(len);
    if (!key_d) {
        return -1;
    }
    memcpy(key_d, key, len);
    
    struct elem_i *val = (struct elem_i *)mem_add(params.mempool, key_d, len, sizeof(struct elem_i));
    if (!val) {
        uniperror("mem_add");
        free(key_d);
        return -1;
    }
    val->m = m;
    val->time = t;
    return 0;
}


int connect_hook(struct poolhd *pool, struct eval *val, 
        const union sockaddr_u *dst, evcb_t next)
{
    int m = cache_get(dst), init_m = m;
    val->cache = (m == 0);
    m = m < 0 ? 0 : m;
    struct desync_params *dp;
    
    for (; ; m++) {
        dp = &params.dp[m];
        if ((!dp->detect || m == init_m)
                && check_l34(dp, SOCK_STREAM, dst)) {
            break;
        }
        if (m == params.dp_count) {
            return -1;
        }
    }
    val->attempt = m;
    
    if (dp->custom_dst) {
        union sockaddr_u addr = dp->custom_dst_addr;
        addr.in6.sin6_port = dst->in6.sin6_port;
        
        return create_conn(pool, val, &addr, next);
    }
    return create_conn(pool, val, dst, next);
}


int socket_mod(int fd)
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


static int reconnect(struct poolhd *pool, struct eval *val, int m)
{
    assert(val->flag == FLAG_CONN);
    
    struct eval *client = val->pair;
    
    if (create_conn(pool, client, &val->addr, &on_tunnel)) {
        return -1;
    }
    val->pair = 0;
    del_event(pool, val);
    
    client->cb = &on_tunnel;
    client->attempt = m;
    client->cache = 1;
    
    if (!client->buff) {
        client->buff = buff_pop(pool, client->sq_buff->size);
    }
    client->buff->lock = client->sq_buff->lock;
    memcpy(client->buff->data, client->sq_buff->data, client->buff->lock);
    
    client->buff->offset = 0;
    client->round_sent = 0;
    client->part_sent = 0;
    return 0;
}


static bool check_host(
        struct mphdr *hosts, const char *buffer, ssize_t n)
{
    char *host = 0;
    int len;
    if (!(len = parse_tls(buffer, n, &host))) {
        len = parse_http(buffer, n, &host, 0);
    }
    assert(len == 0 || host != 0);
    if (len <= 0) {
        return 0;
    }
    struct elem *v = mem_get(hosts, host, len);
    return v && v->len <= len;
}


static bool check_ip(
        struct mphdr *ipset, const union sockaddr_u *dst)
{
    int len = sizeof(dst->in.sin_addr);
    const char *data = (const char *)&dst->in.sin_addr;
    
    if (dst->sa.sa_family == AF_INET6) {
        len = sizeof(dst->in6.sin6_addr);
        data = (const char *)&dst->in6.sin6_addr;
    }
    if (mem_get(ipset, data, len * 8)) {
        return 1;
    }
    return 0;
}


static bool check_proto_tcp(int proto, const char *buffer, ssize_t n)
{
    if (!(proto & ~IS_IPV4)) {
        return 1;
    }
    else if ((proto & IS_HTTP) && 
            is_http(buffer, n)) {
        return 1;
    }
    else if ((proto & IS_HTTPS) && 
            is_tls_chello(buffer, n)) {
        return 1;
    }
    return 0;
}


static bool check_l34(struct desync_params *dp, int st, const union sockaddr_u *dst)
{
    if ((dp->proto & IS_UDP) && (st != SOCK_DGRAM)) {
        return 0;
    }
    if ((dp->proto & IS_TCP) && (st != SOCK_STREAM)) {
        return 0;
    }
    if (dp->proto & IS_IPV4) {
        static const char *pat = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
        
        if (dst->sa.sa_family != AF_INET 
                && memcmp(&dst->in6.sin6_addr, pat, 12)) {
            return 0;
        }
    }
    if (dp->pf[0] && 
            (dst->in.sin_port < dp->pf[0] || dst->in.sin_port > dp->pf[1])) {
        return 0;
    }
    if (dp->ipset && !check_ip(dp->ipset, dst)) {
        return 0;
    }
    return 1;
}


static bool check_round(const int *nr, int r)
{
    return (!nr[1] && r <= 1) || (r >= nr[0] && r <= nr[1]);
}


static int on_trigger(int type, struct poolhd *pool, struct eval *val)
{
    int m = val->pair->attempt + 1;
    
    struct buffer *pair_buff = val->pair->sq_buff;
    bool can_reconn = (
        pair_buff && pair_buff->lock && !val->recv_count
        && params.auto_level > AUTO_NOBUFF
    );
    if (!can_reconn && params.auto_level <= AUTO_NOSAVE) {
        return -1;
    }
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if (!dp->detect) {
            break;
        }
        if (!(dp->detect & type)) {
            continue;
        }
        if (can_reconn) {
            return reconnect(pool, val, m);
        }
        cache_add(&val->addr, m);
        break;
    }
    if (m >= params.dp_count && m > 1) {
        cache_add(&val->addr, 0);
    }
    return -1;
}


static int on_torst(struct poolhd *pool, struct eval *val)
{
    if (on_trigger(DETECT_TORST, pool, val) == 0) {
        return 0;
    }
    struct linger l = { .l_onoff = 1 };
    if (setsockopt(val->pair->fd, SOL_SOCKET,
            SO_LINGER, (char *)&l, sizeof(l)) < 0) {
        uniperror("setsockopt SO_LINGER");
    }
    return -1;
}


static int on_fin(struct poolhd *pool, struct eval *val)
{
    if (!(val->pair->mark && val->round_count <= 1)) {
        return -1;
    }
    if (on_trigger(DETECT_TLS_ERR, pool, val) == 0) {
        return 0;
    }
    return -1;
}


static int on_response(struct poolhd *pool, struct eval *val, 
        const char *resp, ssize_t sn)
{
    int m = val->pair->attempt + 1;
    
    char *req = val->pair->sq_buff->data;
    ssize_t qn = val->pair->sq_buff->size;
    
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


static inline void free_first_req(struct poolhd *pool, struct eval *client)
{
    buff_push(pool, client->sq_buff);
    client->sq_buff = 0;
}


static int setup_conn(struct eval *client, const char *buffer, ssize_t n)
{
    int m = client->attempt, init_m = m;
    
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        if ((!dp->detect || m == init_m)
                && (m == init_m || check_l34(dp, SOCK_STREAM, &client->pair->addr))
                && check_proto_tcp(dp->proto, buffer, n) 
                && (!dp->hosts || check_host(dp->hosts, buffer, n))) {
            break;
        }
    }
    if (m >= params.dp_count) {
        LOG(LOG_E, "drop connection (m=%d)\n", m);
        return -1;
    }
    if (params.auto_level > AUTO_NOBUFF && params.dp_count > 1) {
        client->mark = is_tls_chello(buffer, n);
    }
    client->attempt = m;
    
    if (params.timeout 
            && set_timeout(client->pair->fd, params.timeout)) {
        return -1;
    }
    if (pre_desync(client->pair->fd, client->attempt)) {
        return -1;
    }
    return 0;
}


static int cancel_setup(struct eval *remote)
{
    if (params.timeout && params.auto_level <= AUTO_NOSAVE &&
            set_timeout(remote->fd, 0)) {
        return -1;
    }
    if (post_desync(remote->fd, remote->pair->attempt)) {
        return -1;
    }
    return 0;
}


ssize_t tcp_send_hook(struct poolhd *pool, 
        struct eval *remote, struct buffer *buff, ssize_t *n, bool *wait)
{
    ssize_t sn = -1;
    int skip = remote->flag != FLAG_CONN; 
    size_t off = buff->offset;
    
    if (!skip) {
        struct eval *client = remote->pair;
    
        if (client->recv_count == *n 
                && setup_conn(client, buff->data, *n) < 0) {
            return -1;
        }
        int m = client->attempt, r = client->round_count;
        if (!check_round(params.dp[m].rounds, r)) {
            skip = 1;
        }
        else {
            LOG(LOG_S, "desync TCP: group=%d, round=%d, fd=%d\n", m, r, remote->fd);
            sn = desync(pool, remote, buff, n, wait);
        }
    }
    if (skip) {
        sn = send(remote->fd, buff->data + off, *n - off, 0);
        if (sn < 0 && get_e() == EAGAIN) {
            return 0;
        }
    }
    remote->pair->round_sent += sn;
    return sn;
}


ssize_t tcp_recv_hook(struct poolhd *pool, 
        struct eval *val, struct buffer *buff)
{
    ssize_t n = recv(val->fd, buff->data, buff->size, 0);
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
    val->recv_count += n;
    if (val->round_sent == 0) {
        val->round_count++;
        val->pair->round_sent = 0;
        val->pair->part_sent = 0;
    }
    if (val->flag == FLAG_CONN && !val->round_sent) {
        int *nr = params.dp[val->pair->attempt].rounds;
        
        if (check_round(nr, val->round_count)
                && !check_round(nr, val->round_count + 1)
                && cancel_setup(val)) {
            return -1;
        }
    }
    //
    if (val->flag != FLAG_CONN 
            && !val->pair->recv_count 
            && params.auto_level > AUTO_NOBUFF
            && (val->sq_buff || val->recv_count == n))
    {
        if (!val->sq_buff) {
            if (!(val->sq_buff = buff_pop(pool, buff->size))) {
                return -1;
            }
        }
        val->sq_buff->lock += n;
        
        if ((size_t )val->sq_buff->lock >= val->sq_buff->size) {
            free_first_req(pool, val);
        }
        else {
            memcpy(val->sq_buff->data + val->sq_buff->lock - n, buff->data, n);
        }
    }
    else if (val->pair->sq_buff) {
        if (on_response(pool, val, buff->data, n) == 0) {
            return 0;
        }
        free_first_req(pool, val->pair);
        int m = val->pair->attempt;
        
        if (val->pair->cache && cache_add(&val->addr, m) < 0) {
            return -1;
        }
    }
    return n;
}


ssize_t udp_hook(struct eval *val, 
        char *buffer, ssize_t n, const union sockaddr_u *dst)
{
    struct eval *pair = val->pair->pair;
    
    int m = pair->attempt, r = pair->round_count;
    if (!m) {
        for (; m < params.dp_count; m++) {
            struct desync_params *dp = &params.dp[m];
            if (!dp->detect 
                    && check_l34(dp, SOCK_DGRAM, dst)) {
                break;
            }
        }
        if (m >= params.dp_count) {
            return -1;
        }
        pair->attempt = m;
    }
    if (!check_round(params.dp[m].rounds, r)) {
        return send(val->fd, buffer, n, 0);
    }
    LOG(LOG_S, "desync UDP: group=%d, round=%d, fd=%d\n", m, r, val->fd);
    return desync_udp(val->fd, buffer, n, &dst->sa, m);
}


#ifdef __linux__
static int protect(int conn_fd, const char *path)
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
    char buf[CMSG_SPACE(sizeof(fd))] = { 0 };
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
