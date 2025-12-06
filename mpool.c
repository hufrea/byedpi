#include "mpool.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>


static int bit_cmp(const struct elem *p, const struct elem *q)
{
    int len = q->len < p->len ? q->len : p->len;
    int df = len % 8, bytes = len / 8;
    int cmp = memcmp(p->data, q->data, bytes);
    
    if (cmp || !df) {
        return cmp;
    }
    uint8_t c1 = p->data[bytes] >> (8 - df);
    uint8_t c2 = q->data[bytes] >> (8 - df);
    if (c1 != c2) {
        if (c1 < c2) return -1;
        else return 1;
    }
    return 0;
}


static int byte_cmp(const struct elem *p, const struct elem *q)
{
    if (p->len != q->len) {
        return p->len < q->len ? -1 : 1;
    }
    return memcmp(p->data, q->data, p->len);
}


static int host_cmp(const struct elem *p, const struct elem *q)
{
    int len = q->len < p->len ? q->len : p->len;
    char *pd = p->data + p->len, *qd = q->data + q->len;
    
    while (len-- > 0) {
        if (*--pd != *--qd) {
            return *pd < *qd ? -1 : 1;
        }
    }
    if (p->len == q->len 
            || (p->len > q->len ? pd[-1] : qd[-1]) == '.')
        return 0;
    
    return p->len > q->len ? 1 : -1;
}


static int scmp(const struct elem *p, const struct elem *q)
{
    switch (p->cmp_type) {
    case CMP_BITS:
        return bit_cmp(p, q);
    case CMP_HOST:
        return host_cmp(p, q);
    default:
        return byte_cmp(p, q);
    }
}

KAVL_INIT(my, struct elem, head, scmp)


struct mphdr *mem_pool(unsigned short flags, unsigned char cmp_type)
{
    struct mphdr *hdr = calloc(1, sizeof(struct mphdr));
    if (hdr) {
        hdr->flags = flags;
        hdr->cmp_type = cmp_type;
    }
    return hdr;
}


void *mem_get(const struct mphdr *hdr, const char *str, int len)
{
    struct elem temp = { 
        .cmp_type = hdr->cmp_type,
        .len = len, .data = (char *)str 
    };
    return kavl_find(my, hdr->root, &temp, 0);
}


static void destroy_elem(struct mphdr *hdr, struct elem *e)
{
    if (!(hdr->flags & MF_STATIC)) {
        free(e->data);
    }
    if (hdr->flags & MF_EXTRA) {
        free(((struct elem_ex *)e)->extra);
    }
    free(e);
}


void *mem_add(struct mphdr *hdr, char *str, int len, size_t struct_size)
{
    struct elem *v, *e = calloc(1, struct_size);
    if (!e) {
        return 0;
    }
    e->len = len;
    e->cmp_type = hdr->cmp_type;
    e->data = str;
    
    v = kavl_insert(my, &hdr->root, e, 0);
    while (e != v && e->len < v->len) {
        mem_delete(hdr, v->data, v->len);
        v = kavl_insert(my, &hdr->root, e, 0);
    }
    if (e != v) {
        destroy_elem(hdr, e);
    }
    else hdr->count++;
    return v;
}


void mem_delete(struct mphdr *hdr, const char *str, int len)
{
    struct elem temp = { 
        .cmp_type = hdr->cmp_type,
        .len = len, .data = (char *)str 
    };
    struct elem *e = kavl_erase(my, &hdr->root, &temp, 0);
    if (!e) {
        return;
    }
    destroy_elem(hdr, e);
    hdr->count--;
}


void mem_destroy(struct mphdr *hdr)
{
    while (hdr && hdr->root) {
        struct elem *e = kavl_erase_first(my, &hdr->root);
        if (!e) {
            break;
        }
        destroy_elem(hdr, e);
    }
    free(hdr);
}


void dump_cache(struct mphdr *hdr, FILE *out)
{
    if (!hdr->root) {
        return;
    }
    time_t now = time(0);
    
    kavl_itr_t(my) itr;
    kavl_itr_first(my, hdr->root, &itr);
    do {
        struct elem_i *p = (struct elem_i *)kavl_at(&itr);
        struct cache_key *key = (struct cache_key *)p->main.data;
        
        char ADDR_STR[INET6_ADDRSTRLEN];
        if (key->family == AF_INET)
            inet_ntop(AF_INET, &key->ip.v4, ADDR_STR, sizeof(ADDR_STR));
        else
            inet_ntop(AF_INET6, &key->ip.v6, ADDR_STR, sizeof(ADDR_STR));
        
        if (now > p->time + params.cache_ttl[p->time_inc - 1]) {
            continue;
        }
        fprintf(out, "0 %s %d %lu %jd %d %.*s\n", 
            ADDR_STR, ntohs(key->port), p->dp_mask,
            (intmax_t)p->time, p->time_inc, p->extra_len, p->extra ? p->extra : "");
    } 
    while (kavl_itr_next(my, &itr));
    fflush(out);
}


void load_cache(struct mphdr *hdr, FILE *in)
{
    time_t now = time(0);
    for (int i = 0; ; i++) {
        char addr_str[INET6_ADDRSTRLEN] = { 0 };
        char host[256] = { 0 };
        
        uint16_t port;
        uint64_t mask = 0;
        time_t cache_time;
        int cache_inc;
        
        int c = fscanf(in, "0 %39s %hu %lu %jd %d %255s\n", 
            addr_str, &port, &mask, &cache_time, &cache_inc, host);
        if (c < 1) {
            return;
        }
        if (cache_inc > params.cache_ttl_n) {
            continue;
        }
        struct cache_key key = { 0 };
        size_t key_size = offsetof(struct cache_key, ip.v4);
        
        if (inet_pton(AF_INET, addr_str, &key.ip.v4) <= 0) {
            if (inet_pton(AF_INET6, addr_str, &key.ip.v6) <= 0) {
                continue;
            } else {
                key.family = AF_INET6;
                key_size += sizeof(key.ip.v6);
            }
        }
        else {
            key.family = AF_INET;
            key_size += sizeof(key.ip.v4);
        }
        key.port = htons(port);
        
        struct cache_key *data = calloc(1, key_size);
        if (!data) {
            return;
        }
        memcpy(data, &key, key_size);
        
        struct elem_i *e = mem_add(hdr, (char *)data, key_size, sizeof(struct elem_i));
        if (!e) {
            free(data);
            return;
        }
        e->detect = 0xffffffff;
        e->dp_mask = mask;
        e->time = cache_time;
        e->time_inc = cache_inc;
        e->extra_len = strlen(host);
        
        if (e->extra_len) {
            e->extra = malloc(e->extra_len + 1);
            memcpy(e->extra, host, e->extra_len + 1);
        }
    }
}

