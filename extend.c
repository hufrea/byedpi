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

#include "proxy.h"
#include "error.h"
#include "params.h"

#include <desync.h>
#include <packets.h>


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
    time_t t;
    struct elem *val;
    char *str = (char *)&dst->in;
    int len = sizeof(dst->sa.sa_family);
    
    if (dst->sa.sa_family == AF_INET) {
        len = sizeof(dst->in);
    }
    else {
        len = sizeof(dst->in6) - sizeof(dst->in6.sin6_scope_id);
    }
    len -= sizeof(dst->sa.sa_family);
    
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


int ext_connect(struct poolhd *pool, struct eval *val, 
        struct sockaddr_ina *dst, int next, int m)
{
    struct desync_params *dp = &params.dp[m];
    if (dp->to_ip == 2) {
        struct sockaddr_ina addr = { .in6 = dp->addr };
        if (!addr.in.sin_port) {
            addr.in.sin_port = dst->in.sin_port;
        }
        return create_conn(pool, val, &addr, next);
    }
    return create_conn(pool, val, dst, next);
}


int connect_hook(struct poolhd *pool, struct eval *val, 
        struct sockaddr_ina *dst, int next)
{
    int m = mode_add_get(dst, -1);
    val->cache = (m == 0);
    val->attempt = m < 0 ? 0 : m;
    
    if (params.late_conn) {
        val->type = EV_DESYNC;
        if (resp_error(val->fd, 0, val->flag) < 0) {
            perror("send");
            return -1;
         }
         val->in6 = dst->in6;
         return 0;
    }
    return ext_connect(pool, val, dst, next, m);
}


int reconnect(struct poolhd *pool, struct eval *val, int m)
{
    struct eval *client = val->pair;
    
    if (ext_connect(pool, client, 
            (struct sockaddr_ina *)&val->in6, EV_DESYNC, m)) {
        return -1;
    }
    val->pair = 0;
    del_event(pool, val);
    
    client->type = EV_IGNORE;
    client->attempt = m;
    client->cache = 1;
    return 0;
}


bool check_host(struct mphdr *hosts, struct eval *val)
{
    char *host = 0;
    int len;
    if (!(len = parse_tls(val->buff.data, val->buff.size, &host))) {
        len = parse_http(val->buff.data, val->buff.size, &host, 0);
    }
    return (len > 0) && mem_get(hosts, host, len) != 0;
}


bool check_proto_tcp(int proto, struct eval *val)
{
    if ((proto & IS_HTTP) && 
            is_http(val->buff.data, val->buff.size)) {
        return 1;
    }
    if ((proto & IS_HTTPS) && 
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
        if (!(dp->detect & DETECT_TORST)) {
            continue;
        }
        if ((!dp->hosts || check_host(dp->hosts, val->pair)) &&
                (!dp->proto || check_proto_tcp(dp->proto, val))) {
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


int on_response(struct poolhd *pool, struct eval *val, 
        char *resp, ssize_t sn)
{
    int m = val->pair->attempt + 1;
    
    char *req = val->pair->buff.data;
    ssize_t qn = val->pair->buff.size;
    
    for (; m < params.dp_count; m++) {
        struct desync_params *dp = &params.dp[m];
        
        switch (0) {
        default:
            if ((dp->detect & DETECT_HTTP_LOCAT)
                    && is_http_redirect(req, qn, resp, sn)) {
                break;
            }
            else if ((dp->detect & DETECT_TLS_INVSID)
                    && neq_tls_sid(req, qn, resp, sn)) {
                break;
            }
            else if ((dp->detect & DETECT_TLS_ALERT)
                    && is_tls_alert(resp, sn)) {
                break;
            }
            else if (dp->detect & DETECT_HTTP_CLERR) {
                int code = get_http_code(resp, sn);
                if (code > 400 && code < 451 && code != 429) {
                    break;
                }
            }
            continue;
        }
        if ((!dp->hosts || check_host(dp->hosts, val->pair)) &&
                (!dp->proto || check_proto_tcp(dp->proto, val))) {
            break;
        }
    }
    if (m < params.dp_count) {
        return reconnect(pool, val, m);
    }
    return -1;
}


int on_tunnel_check(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize, int out)
{
    if (out) {
        return on_tunnel(pool, val, buffer, bfsize, out);
    }
    ssize_t n = recv(val->fd, buffer, bfsize, 0);
    if (n < 1) {
        uniperror("recv");
        switch (get_e()) {
            case ECONNRESET:
            case ETIMEDOUT: 
                break;
            default: return -1;
        }
        return on_torst(pool, val);
    }
    //
    if (on_response(pool, val, buffer, n) == 0) {
        return 0;
    }
    struct eval *pair = val->pair;
    
    ssize_t sn = send(pair->fd, buffer, n, 0);
    if (n != sn) {
        uniperror("send");
        return -1;
    }
    val->type = EV_TUNNEL;
    pair->type = EV_TUNNEL;
    
    free(pair->buff.data);
    pair->buff.data = 0;
    pair->buff.size = 0;
    
    if (params.timeout &&
            set_timeout(val->fd, 0)) {
        return -1;
    }
    int m = pair->attempt;
    
    if (!pair->cache) {
        return 0;
    }
    if (m == 0) {
        LOG(LOG_S, "delete ip: m=%d\n", m);
    } else {
        LOG(LOG_S, "save ip: m=%d\n", m);
    }
    return mode_add_get(
        (struct sockaddr_ina *)&val->in6, m);
}


int on_desync(struct poolhd *pool, struct eval *val,
        char *buffer, size_t bfsize)
{
    if (val->flag == FLAG_CONN) {
        if (mod_etype(pool, val, POLLOUT, 0)) {
            uniperror("mod_etype");
            return -1;
        }
        val = val->pair;
    }
    ssize_t n;
    int m = val->attempt;
    LOG((m ? LOG_S : LOG_L), "desync params index: %d\n", m);
    
    if (!val->buff.data) {
        n = recv(val->fd, buffer, bfsize, 0);
        if (n <= 0) {
            if (n) uniperror("recv data");
            return -1;
        }
        val->buff.size = n;
        val->recv_count += n;
        
        if (!(val->buff.data = malloc(n))) {
            uniperror("malloc");
            return -1;
        }
        memcpy(val->buff.data, buffer, n);
        
        if (!m) for (; m < params.dp_count; m++) {
            struct desync_params *dp = &params.dp[m];
            if (!dp->detect &&
                    (!dp->hosts || check_host(dp->hosts, val)) &&
                    (!dp->proto || check_proto_tcp(dp->proto, val))) {
                break;
            }
        }
        if (m >= params.dp_count) {
            return -1;
        }
        val->attempt = m;
        
        if (params.late_conn) {
            return ext_connect(pool, val, 
                (struct sockaddr_ina *)&val->in6, EV_DESYNC, m);
        }
    }
    else {
        n = val->buff.size;
        memcpy(buffer, val->buff.data, n);
    }
    if (params.timeout &&
            set_timeout(val->pair->fd, params.timeout)) {
        return -1;
    }
    ssize_t sn = desync(val->pair->fd, buffer, bfsize,
        n, val->buff.offset, (struct sockaddr *)&val->pair->in6, m);
    if (sn < 0) {
        return -1;
    }
    if (sn < n) {
        val->buff.offset = sn;
        if (mod_etype(pool, val->pair, POLLOUT, 1)) {
            uniperror("mod_etype");
            return -1;
        }
        val->pair->type = EV_DESYNC;
        return 0;
    }
    val->type = EV_TUNNEL;
    val->pair->type = EV_PRE_TUNNEL;
    return 0;
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
