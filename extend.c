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
        struct cache_key *out)
{
    out->port = dst->in.sin_port;
    out->family = dst->sa.sa_family;
    static const ssize_t c = offsetof(struct cache_key, ip.v4);
    
    if (dst->sa.sa_family == AF_INET) {
        out->ip.v4 = dst->in.sin_addr;
        return c + sizeof(out->ip.v4);
    } 
    else {
        out->ip.v6 = dst->in6.sin6_addr;
        return c + sizeof(out->ip.v6);
    }
}


static struct elem_i *cache_get(const union sockaddr_u *dst)
{
    struct cache_key key = { 0 };
    int len = serialize_addr(dst, &key);
    
    struct elem_i *val = mem_get(params.mempool, (char *)&key, len);
    if (!val) {
        return 0;
    }
    time_t t = time(0);
    if (t > val->time + params.cache_ttl[val->time_inc - 1]) {
        LOG(LOG_S, "ignore: time=%jd, now=%jd, inc=%d\n", (intmax_t)val->time, (intmax_t)t, val->time_inc);
        return 0;
    }
    return val;
}


static struct elem_i *cache_add(
        const union sockaddr_u *dst, char **host, int host_len)
{
    struct cache_key key = { 0 };
    int cmp_len = serialize_addr(dst, &key);
    time_t t = time(0);
    
    struct cache_key *data = calloc(1, cmp_len);
    if (!data) {
        return 0;
    }
    memcpy(data, &key, cmp_len);
    
    struct elem_i *val = mem_add(params.mempool, (char *)data, cmp_len, sizeof(struct elem_i));
    if (!val) {
        uniperror("mem_add");
        free(data);
        return 0;
    }
    val->time = t;
    if (val->time_inc < params.cache_ttl_n) {
        val->time_inc++;
    }
    if (!val->extra && *host) {
        val->extra_len = host_len;
        val->extra = *host;
        *host = 0;
    }
    return val;
}


int on_socks_recv(struct poolhd *pool, struct eval *val, int t)
{
    struct s5_req r = { 0 };
    
    ssize_t n = recv(val->fd, (char *)&r, sizeof(r), 0);
    if (n < 2) {
        uniperror("socks recv");
        return on_torst(pool, val);
    }
    if (r.ver != S_VER5 || r.cmd != 0x00) {
        LOG(LOG_E, "socks answer: %d\n", r.cmd);
        return on_torst(pool, val);
    }
    if (val->conn_state != FLAG_S5) {
        r.cmd = S_CMD_CONN;
        int len = s5_set_addr((char *)&r, sizeof(r), &val->addr, 0);
        
        if (send(val->fd, (char *)&r, len, 0) < 0) {
            uniperror("socks send");
            return on_torst(pool, val);
        }
        val->conn_state = FLAG_S5;
        return 0;
    }
    val->cb = val->after_conn_cb;
    
    return (val->cb)(pool, val, POLLOUT);
}

int on_socks_conn(struct poolhd *pool, struct eval *val, int t)
{
    static const char data[3] = "\x05\x01";
    
    if (send(val->fd, (char *)data, sizeof(data), 0) < 0) {
        uniperror("socks send");
        return on_torst(pool, val);
    }
    if (mod_etype(pool, val, POLLIN) ||
            mod_etype(pool, val->pair, POLLIN)) {
        uniperror("mod_etype");
        return -1;
    }
    val->cb = &on_socks_recv;
    return 0;
}


int connect_hook(struct poolhd *pool, struct eval *val, 
        const union sockaddr_u *dst, evcb_t next)
{
    struct desync_params *dp = params.dp;
    
    if (!val->dp_mask) {
        struct elem_i *e = cache_get(dst);
        if (e) {
            val->dp_mask = e->dp_mask;
            val->detect = e->detect;
        }
    }
    for (; ; dp = dp->next) {
        if (!dp) {
            return -1;
        }
        if (!(dp->bit & val->dp_mask) 
                && (!dp->detect || (val->detect & dp->detect))
                && check_l34(dp, SOCK_STREAM, dst)) {
            break;
        }
        val->dp_mask |= dp->bit;
    }
    val->dp = dp;
    
    if (dp->ext_socks.in6.sin6_port) {
        int e = create_conn(pool, val, &dp->ext_socks, &on_socks_conn);
        if (!e) {
            val->pair->after_conn_cb = next;
            val->pair->addr = *dst;
        }
        return e;
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


static int reconnect(struct poolhd *pool, struct eval *val)
{
    assert(val->flag == FLAG_CONN);
    
    struct eval *client = val->pair;
    
    if (connect_hook(pool, client, &val->addr, 
            client->sq_buff ? &on_tunnel : &on_connect)) {
        return -1;
    }
    val->pair = 0;
    del_event(pool, val);
    
    client->cb = &on_tunnel;
    
    if (client->sq_buff) {
        if (!client->buff) {
            client->buff = buff_pop(pool, client->sq_buff->size);
        }
        client->buff->lock = client->sq_buff->lock;
        memcpy(client->buff->data, client->sq_buff->data, client->buff->lock);
        
        client->buff->offset = 0;
    }
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


static void swop_groups(struct desync_params *dpc, struct desync_params *dpn)
{
    LOG(LOG_S, "swop: %d <-> %d\n", dpc->id, dpn->id);
    
    struct desync_params dpc_cp = *dpc;
    dpc->next = dpn->next;
    dpc->prev = dpn->prev;
    
    dpn->prev = dpc_cp.prev;
    dpn->next = dpc_cp.next;
    
    if (dpn->prev) 
        dpn->prev->next = dpn;
    
    if (dpc->next)
        dpc->next->prev = dpc;
    
    if (dpc_cp.next != dpn) {
        dpn->next->prev = dpn;
        dpc->prev->next = dpc;
    } 
    else {
        dpc->prev = dpn;
        dpn->next = dpc;
    }
    dpc->detect = dpn->detect;
    dpn->detect = dpc_cp.detect;
    
    if (params.dp == dpc) params.dp = dpn;
}


static int on_trigger(int type, struct poolhd *pool, struct eval *val, bool client_alive)
{
    struct eval *lav = val->pair;
    
    bool before_req = !lav->recv_count && !val->recv_count;
    
    bool can_reconn = ((lav->sq_buff || before_req)
        && (params.auto_level & AUTO_RECONN) && client_alive
    );
    if (!can_reconn && !(params.auto_level & AUTO_POST)) {
        return -1;
    }
    INIT_ADDR_STR((val->addr));
    
    struct elem_i *cache = cache_add(&val->addr, &lav->host, lav->host_len);
    if (!cache) {
        return -1;
    }
    lav->dp->fail_count++;
    lav->dp_mask |= lav->dp->bit;
    lav->detect = type;
    
    uint64_t uncheked = lav->dp_mask;
    struct desync_params *dp = params.dp, *next = 0;
    
    for (; dp; dp = dp->next) {
        if (!uncheked && !dp->detect) {
            break;
        }
        if (!(dp->bit & lav->dp_mask)
                && (!dp->detect || (dp->detect & type))) {
            next = dp;
            break;
        }
        uncheked &= ~dp->bit;
        lav->dp_mask |= dp->bit;
    }
    if ((params.auto_level & AUTO_SORT) 
            && !(lav->dp->bit & cache->dp_mask)) 
    {
        if (next && lav->dp->pri > next->pri
                && !(lav->dp->bit & uncheked)) {
            swop_groups(lav->dp, next);
        }
        lav->dp->pri++;
    }
    if (!next) {
        LOG(LOG_S, "unreach ip: %s\n", ADDR_STR);
        cache->dp_mask = 0;
        cache->detect = 0;
        return -1;
    }
    LOG(LOG_S, "save: ip=%s, id=%d\n", ADDR_STR, next->id);
    
    cache->dp_mask |= lav->dp_mask;
    cache->detect = lav->detect;
    
    if (can_reconn) {
        return reconnect(pool, val);
    }
    return -1;
}


int on_torst(struct poolhd *pool, struct eval *val)
{
    if (on_trigger(DETECT_TORST, pool, val, 1) == 0) {
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
    bool is_client = val->flag != FLAG_CONN;
    
    if (is_client) {
        val = val->pair;
    }
    if (!(val->pair->mark && val->round_count <= 1)) {
        return -1;
    }
    if (on_trigger(DETECT_TLS_ERR, pool, val, !is_client) == 0) {
        return 0;
    }
    return -1;
}


static int on_response(struct poolhd *pool, struct eval *val, 
        const char *resp, ssize_t sn)
{
    struct desync_params *dp = params.dp;
    
    char *req = val->pair->sq_buff->data;
    ssize_t qn = val->pair->sq_buff->size;
    
    val->pair->dp_mask |= val->pair->dp->bit;
    
    for (; dp; dp = dp->next) {
        if (dp->bit & val->pair->dp_mask) {
            continue;
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
    if (dp) {
        return on_trigger(dp->detect, pool, val, 1);
    }
    return -1;
}


static inline void free_first_req(struct poolhd *pool, struct eval *client)
{
    buff_push(pool, client->sq_buff);
    client->sq_buff = 0;
}


static void save_hostname(struct eval *client, const char *buffer, ssize_t n)
{
    if (client->host) {
        return;
    }
    char *host = 0;
    int len = parse_tls(buffer, n, &host);
    if (!len) {
        if (!(len = parse_http(buffer, n, &host, 0))) {
            return;
        }
    }
    if (!(client->host = malloc(len))) {
        return;
    }
    memcpy(client->host, host, len);
    client->host_len = len;
}


static int setup_conn(struct eval *client, const char *buffer, ssize_t n)
{
    if (params.cache_file) {
        save_hostname(client, buffer, n);
    }
    struct desync_params *dp = client->dp, *init_dp = client->dp;
    
    for (; dp; dp = dp->next) {
        if (!(dp->bit & client->dp_mask) 
                && (!dp->detect || (client->detect & dp->detect))
                && (dp == init_dp || check_l34(dp, SOCK_STREAM, &client->pair->addr))
                && check_proto_tcp(dp->proto, buffer, n) 
                && (!dp->hosts || check_host(dp->hosts, buffer, n))) {
            break;
        }
        client->dp_mask |= dp->bit;
    }
    if (!dp) {
        LOG(LOG_E, "drop connection\n");
        return -1;
    }
    if ((params.auto_level & (AUTO_POST | AUTO_RECONN)) && params.dp->next) {
        client->mark = is_tls_chello(buffer, n);
    }
    client->dp = dp;
    
    if (params.timeout 
            && set_timeout(client->pair->fd, params.timeout)) {
        return -1;
    }
    if (pre_desync(client->pair->fd, client->dp)) {
        return -1;
    }
    return 0;
}


static int cancel_setup(struct eval *remote)
{
    if (params.timeout && !(params.auto_level & AUTO_POST) &&
            set_timeout(remote->fd, 0)) {
        return -1;
    }
    if (post_desync(remote->fd, remote->pair->dp)) {
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
        int r = client->round_count;
        if (!check_round(client->dp->rounds, r)) {
            skip = 1;
        }
        else {
            LOG(LOG_S, "desync TCP: group=%d, round=%d, fd=%d\n", client->dp->id, r, remote->fd);
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
            case EHOSTUNREACH:
                if (val->flag == FLAG_CONN)
                    return on_torst(pool, val);
                else
                    return on_fin(pool, val);
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
        int *nr = val->pair->dp->rounds;
        
        if (check_round(nr, val->round_count)
                && !check_round(nr, val->round_count + 1)
                && cancel_setup(val)) {
            return -1;
        }
    }
    //
    if (val->flag != FLAG_CONN 
            && !val->pair->recv_count 
            && (params.auto_level & AUTO_RECONN)
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
    }
    return n;
}


ssize_t udp_hook(struct eval *val, 
        char *buffer, ssize_t n, const union sockaddr_u *dst)
{
    struct eval *pair = val->pair->pair;
    int r = pair->round_count;
    
    struct desync_params *dp = pair->dp;
    if (!dp) {
        for (dp = params.dp; ; dp = dp->next) {
            if (!dp) {
                return -1;
            }
            if (!dp->detect 
                    && check_l34(dp, SOCK_DGRAM, dst)) {
                break;
            }
        }
        pair->dp = dp;
    }
    if (!check_round(dp->rounds, r)) {
        return send(val->fd, buffer, n, 0);
    }
    LOG(LOG_S, "desync UDP: group=%d, round=%d, fd=%d\n", dp->id, r, val->fd);
    return desync_udp(val->fd, buffer, n, &dst->sa, dp);
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
