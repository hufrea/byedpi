#include "resolve.h"

#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <openssl/ssl.h>

#ifdef _WIN32
    #include <ws2tcpip.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
#endif

#include "params.h"
#include "proxy.h"
#include "error.h"
#include "ssl_compat.h"

#define FLAG_QR 15
#define FLAG_OPCODE 14
#define FLAG_AA 10
#define FLAG_TC 9
#define FLAG_RD 8
#define FLAG_RA 7
#define FLAG_Z 6
#define FLAG_RCODE 3

#define TYPE_A 1
#define TYPE_CNAME 5
#define TYPE_AAAA 28

#define CLASS_INET 1

struct header {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
};

static SSL_CTX *ctx = NULL;

int make_dns_request(
    uint16_t id,
    const uint8_t *qname,
    int qname_len,
    uint16_t qtype,
    uint16_t qclass,
    uint8_t **packet_out
);

int parse_dns_response(
    uint8_t *buf,
    int buf_len,
    uint16_t id,
    const char *debug_hostname,
    int debug_hostname_len,
    union sockaddr_u *addr_out,
    uint8_t **cname_qname_out,
    int *cname_len_out
);

int hostname_dot_to_dns(const char *src, int len, uint8_t *dst);

int resolve_system(const char *hostname, int len, union sockaddr_u *addr_out) 
{
    struct addrinfo hints = {0}, *res = 0;
    
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_ADDRCONFIG;
    hints.ai_family = params.ipv6 ? AF_UNSPEC : AF_INET;
    
    char host[len + 1];
    host[len] = 0;
    memcpy(host, hostname, len);
    
    if (getaddrinfo(host, 0, &hints, &res) || !res) {
        return -1;
    }
    memcpy(addr_out, res->ai_addr, SA_SIZE(res->ai_addr));
    freeaddrinfo(res);
    
    return 0;
}

int resolve_plain_inner(
    const uint8_t *qname,
    int qname_len,
    uint16_t qtype,
    uint16_t qclass,
    union sockaddr_u *addr_out,
    const char* debug_hostname,
    int debug_hostname_len,
    int cname_rec
) {
    uint16_t id = rand();
    
    uint8_t *packet;
    int packet_len = make_dns_request(id, qname, qname_len, qtype, qclass, &packet);
    if (packet_len < 0) {
        return -1;
    }
    
    union sockaddr_u *ns_addr = &params.dns_addr;
    
    int fd = socket(ns_addr->sa.sa_family, SOCK_DGRAM, 0);
    if (fd < 0) {
        free(packet);
        return -1;
    }
    
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(fd);
        free(packet);
        return -1;
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(fd);
        free(packet);
        return -1;
    }
    
    if (connect(fd, &ns_addr->sa, sizeof(ns_addr->sa)) < 0) {
        close(fd);
        free(packet);
        return -1;
    }
    
    if (write(fd, packet, packet_len) < 0) {
        close(fd);
        free(packet);
        return -1;
    }
    free(packet);
    
    uint8_t buf[512];
    if (read(fd, buf, sizeof(buf)) <= 0) {
        close(fd);
        return -1;
    }
    close(fd);
    
    uint8_t *cname_qname = NULL;
    int cname_len;
    if (parse_dns_response(buf, sizeof(buf), id, debug_hostname, debug_hostname_len, addr_out, &cname_qname, &cname_len) < 0) {
        return -1;
    }
    
    if (cname_qname) {
        if (cname_rec >= 10) {
            LOG(LOG_S, "failed to resolve '%.*s': CNAME chain too long\n", debug_hostname_len, debug_hostname);
            return -1;
        }
        
        int res = resolve_plain_inner(
            cname_qname,
            cname_len,
            qtype,
            qclass,
            addr_out,
            debug_hostname,
            debug_hostname_len,
            cname_rec + 1
        );
        free(cname_qname);
        
        return res;
    }
    
    return 0;
}

int resolve_plain(const char *hostname, int len, union sockaddr_u *addr_out) {
    uint8_t qname[255];
    int qname_len = hostname_dot_to_dns(hostname, len, qname);
    
    if (qname_len < 0) {
        return -1;
    }
    
    uint16_t qtype = htons(TYPE_A);
    uint16_t qclass = htons(CLASS_INET);
    
    int res = resolve_plain_inner(qname, qname_len, qtype, qclass, addr_out, hostname, len, 0);
    if (res < 0 && params.ipv6) {
        qtype = htons(TYPE_AAAA);
        res = resolve_plain_inner(qname, qname_len, qtype, qclass, addr_out, hostname, len, 0);
    }
    
    return res;
}

int resolve_dot_inner(
    const uint8_t *qname,
    int qname_len,
    uint16_t qtype,
    uint16_t qclass,
    union sockaddr_u *addr_out,
    const char* debug_hostname,
    int debug_hostname_len,
    int cname_rec
) {
    uint16_t id = rand();
    
    uint8_t *packet;
    int packet_len = make_dns_request(id, qname, qname_len, qtype, qclass, &packet);
    if (packet_len < 0) {
        return -1;
    }
    
    int dot_packet_len = packet_len + 2;
    uint8_t *dot_packet = malloc(dot_packet_len);
    int packet_len_be = htons((uint16_t)packet_len);
    memcpy(dot_packet, &packet_len_be, 2);
    memcpy(dot_packet + 2, packet, packet_len);
    free(packet);
    
    union sockaddr_u *ns_addr = &params.dns_addr;
    
    int fd = socket(ns_addr->sa.sa_family, SOCK_STREAM, 0);
    if (fd < 0) {
        free(dot_packet);
        return -1;
    }
    
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout)) < 0) {
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (connect(fd, &ns_addr->sa, sizeof(ns_addr->sa)) < 0) {
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (!ctx) {
        ctx = SSL_CTX_new_fn(TLS_method_fn());
        
        #ifdef __ANDROID__
        SSL_CTX_load_verify_locations_fn(ctx, NULL, "/system/etc/security/cacerts");
        #else
        SSL_CTX_set_default_verify_paths_fn(ctx);
        #endif
        
        SSL_CTX_set_verify_fn(ctx, SSL_VERIFY_PEER, NULL);
    }
    
    SSL *ssl = SSL_new_fn(ctx);
    if (!ssl) {
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (
        !SSL_ctrl_fn(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, (void *)params.dns_hostname)
    ) {
        SSL_free_fn(ssl);
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (!SSL_set_fd_fn(ssl, fd)) {
        SSL_free_fn(ssl);
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (SSL_connect_fn(ssl) < 1) {
        SSL_free_fn(ssl);
        close(fd);
        free(dot_packet);
        return -1;
    }
    
    if (SSL_write_fn(ssl, dot_packet, dot_packet_len) <= 0) {
        SSL_free_fn(ssl);
        close(fd);
        free(dot_packet);
        return -1;
    }
    free(dot_packet);
    
    uint8_t len_buf[2];
    int len_read = SSL_read_fn(ssl, len_buf, sizeof(len_buf));
    if (len_read != 2) {
        SSL_free_fn(ssl);
        close(fd);
        return -1;
    }
    
    uint16_t recv_len = ntohs(*(uint16_t *)len_buf);
    if (recv_len > 1024) {
        SSL_free_fn(ssl);
        close(fd);
        return -1;
    }
    
    uint8_t *buf = malloc(recv_len);
    if (SSL_read_fn(ssl, buf, recv_len) <= 0) {
        SSL_free_fn(ssl);
        close(fd);
        return -1;
    }
    SSL_free_fn(ssl);
    close(fd);
    
    uint8_t *cname_qname = NULL;
    int cname_len;
    if (parse_dns_response(buf, recv_len, id, debug_hostname, debug_hostname_len, addr_out, &cname_qname, &cname_len) < 0) {
        return -1;
    }
    free(buf);
    
    if (cname_qname) {
        if (cname_rec >= 10) {
            LOG(LOG_S, "failed to resolve '%.*s': CNAME chain too long\n", debug_hostname_len, debug_hostname);
            free(cname_qname);
            return -1;
        }
        
        int res = resolve_dot_inner(
            cname_qname,
            cname_len,
            qtype,
            qclass,
            addr_out,
            debug_hostname,
            debug_hostname_len,
            cname_rec + 1
        );
        free(cname_qname);
        
        return res;
    }
    
    return 0;
}

int resolve_dot(const char *hostname, int len, union sockaddr_u *addr_out) {
    uint8_t qname[255];
    int qname_len = hostname_dot_to_dns(hostname, len, qname);
    
    if (qname_len < 0) {
        return -1;
    }
    
    uint16_t qtype = htons(TYPE_A);
    uint16_t qclass = htons(CLASS_INET);
    
    int res = resolve_dot_inner(qname, qname_len, qtype, qclass, addr_out, hostname, len, 0);
    if (res < 0 && params.ipv6) {
        qtype = htons(TYPE_AAAA);
        res = resolve_dot_inner(qname, qname_len, qtype, qclass, addr_out, hostname, len, 0);
    }
    
    return res;
}

int resolve(const char *hostname, int len, union sockaddr_u *addr_out) {
    char hostname_term[len + 1];
    memcpy(hostname_term, hostname, len);
    hostname_term[len] = '\0';
    
    LOG(LOG_S, "resolve: %s\n", hostname_term);
    
    if (inet_pton(AF_INET, hostname_term, &addr_out->in.sin_addr) == 1) {
        addr_out->in.sin_family = AF_INET;
        return 0;
    }
    if (params.ipv6 && inet_pton(AF_INET6, hostname_term, &addr_out->in6.sin6_addr) == 1) {
        addr_out->in6.sin6_family = AF_INET6;
        return 0;
    }
    
    if (!params.resolve) {
        return -1;
    }
    
    switch (params.dns_mode) {
        case 's':
            return resolve_system(hostname, len, addr_out);
        case 'p':
            return resolve_plain(hostname, len, addr_out);
        case 't':
            return resolve_dot(hostname, len, addr_out);
    }
    
    return -1;
}

int make_dns_request(
    uint16_t id,
    const uint8_t *qname,
    int qname_len,
    uint16_t qtype,
    uint16_t qclass,
    uint8_t **packet_out
) {
    int packet_len = sizeof(struct header) + qname_len + 4; // qtype + qclass = 4
    uint8_t *packet = malloc(packet_len);
    if (!packet) {
        return -1;
    }
    memset(packet, 0, packet_len);
    
    struct header *header = (struct header*)packet;
    uint8_t *questions_start = packet + sizeof(struct header);
    
    header->id = id;
    
    uint16_t flags = 0;
    flags |= 1 << FLAG_RD;
    
    header->flags = htons(flags);
    header->qdcount = htons(1);
    
    memcpy(questions_start, qname, qname_len);
    memcpy(questions_start + qname_len, &qtype, sizeof(qtype));
    memcpy(questions_start + qname_len + sizeof(qtype), &qclass, sizeof(qclass));
    
    *packet_out = packet;
    return packet_len;
}

int parse_dns_response(
    uint8_t *buf,
    int buf_len,
    uint16_t id,
    const char *debug_hostname,
    int debug_hostname_len,
    union sockaddr_u *addr_out,
    uint8_t **cname_qname_out,
    int *cname_len_out
) {
    struct header *header = (struct header*)buf;
        
    if (header->id != id) {
        return -1;
    }
    
    uint16_t flags = ntohs(header->flags);
    if (((flags >> FLAG_QR) & 1) != 1) {
        LOG(LOG_S, "failed to resolve '%.*s': nameserver returned invalid response\n", debug_hostname_len, debug_hostname);
        return -1;
    }
    if (((flags >> FLAG_TC) & 1) != 0) {
        LOG(LOG_S, "failed to resolve '%.*s': nameserver returned truncated response which is unsupported\n", debug_hostname_len, debug_hostname);
        return -1;
    }
    if (((flags >> FLAG_RA) & 1) != 1) {
        LOG(LOG_S, "failed to resolve '%.*s': nameserver doesn't support recursive queries\n", debug_hostname_len, debug_hostname);
        return -1;
    }
    if ((flags & 0xf) != 0) {
        LOG(LOG_S, "failed to resolve '%.*s': nameserver failed to resolve hostname\n", debug_hostname_len, debug_hostname);
        return -1;
    }
    
    uint16_t qdcount = ntohs(header->qdcount);
    uint16_t ancount = ntohs(header->ancount);
    if (qdcount != 1 || ancount < 1) {
        LOG(LOG_S, "failed to resolve '%.*s': nameserver failed to resolve hostname\n", debug_hostname_len, debug_hostname);
        return -1;
    }
    
    uint8_t *ptr = buf + sizeof(struct header);
    uint8_t *end = buf + buf_len;
    
    // skip question
    if (*ptr >= 0xC0) {
        ptr += 2;
    } else {
        while (ptr < end && *ptr != 0) {
            ptr += *ptr + 1;
        }
        ptr++;
    }
    if (ptr + 4 > end) return -1;
    ptr += 4;
    
    for (int i = 0; i < ancount; i++) {
        if (ptr >= end) return -1;
        
        if (*ptr >= 0xC0) {
            ptr += 2;
        } else {
            while (ptr < end && *ptr != 0) {
                ptr += *ptr + 1;
            }
            if (ptr >= end) return -1;
            ptr++;
        }
        
        if (ptr + 10 > end) return -1;
        
        uint16_t type = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        uint16_t class = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        uint32_t ttl = ntohl(*(uint32_t*)ptr);
        ptr += 4;
        
        uint16_t rdlength = ntohs(*(uint16_t*)ptr);
        ptr += 2;
        
        if (ptr + rdlength > end) return -1;
        
        if (type == TYPE_A && class == CLASS_INET && rdlength == 4) {
            addr_out->in.sin_family = AF_INET;
            memcpy(&addr_out->in.sin_addr, ptr, 4);
            return 0;
        } else if (type == TYPE_AAAA && class == CLASS_INET && rdlength == 16 && params.ipv6) {
            addr_out->in6.sin6_family = AF_INET6;
            memcpy(&addr_out->in6.sin6_addr, ptr, 16);
            return 0;
        } else if (type == TYPE_CNAME && class == CLASS_INET) {
            uint8_t *cname_qname = malloc(255);
            uint8_t *cname_ptr = ptr;
            uint8_t *cname_dst = cname_qname;
            int cname_len = 0;
            
            while (cname_ptr < ptr + rdlength && *cname_ptr != 0) {
                if (*cname_ptr >= 0xC0) {
                    if (cname_ptr + 1 >= end) return -1;
                    uint16_t offset = ntohs(*(uint16_t*)cname_ptr) & 0x3FFF;
                    if (offset >= (ptr - buf)) return -1; // loop
                    cname_ptr = buf + offset;
                    continue;
                }
                
                uint8_t label_len = *cname_ptr;
                if (cname_len + label_len + 1 >= 255) return -1;
                
                memcpy(cname_dst, cname_ptr, label_len + 1);
                cname_dst += label_len + 1;
                cname_len += label_len + 1;
                cname_ptr += label_len + 1;
            }
            
            *cname_dst = 0;
            cname_len++;
            
            *cname_qname_out = cname_qname;
            *cname_len_out = cname_len;
            
            return 0;
        }
        
        ptr += rdlength;
    }
    
    LOG(LOG_S, "failed to resolve '%.*s': no A/AAAA/CNAME record in response\n", debug_hostname_len, debug_hostname);
    return -1;
}

int hostname_dot_to_dns(const char *src, int len, uint8_t *dst) {
    if (len <= 0 || len > 253 || !dst) {
        return -1;
    }
    
    if (src[0] == '.' || src[len - 1] == '.') {
        return -1;
    }
    
    int dns_hostname_len = 1;
    int label_len = 0;
    
    for (int i = 0; i < len; i++) {
        if (!isascii(src[i])) {
            return -1;
        }
        
        if (src[i] == '.') {
            if (label_len == 0 || label_len > 63) {
                return -1;
            }
            dns_hostname_len += 1 + label_len;
            label_len = 0;
        } else {
            label_len++;
        }
    }
    
    if (label_len == 0 || label_len > 63) {
        return -1;
    }
    dns_hostname_len += 1 + label_len;
    
    uint8_t *ptr = dst;
    uint8_t *label_len_ptr = ptr++;
    label_len = 0;
    
    for (int i = 0; i < len; i++) {
        if (src[i] == '.') {
            *label_len_ptr = (uint8_t)label_len;
            label_len = 0;
            label_len_ptr = ptr++;
        } else {
            *ptr++ = (uint8_t)src[i];
            label_len++;
        }
    }
    
    *label_len_ptr = (uint8_t)label_len;
    *ptr = 0;
    
    return dns_hostname_len;
}
