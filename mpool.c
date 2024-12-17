#include "mpool.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>


static int bit_cmp(const struct elem *p, const struct elem *q)
{
    if (p->len < q->len) {
        return -1;
    }
    int df = q->len % 8, bytes = q->len / 8;
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


static int scmp(const struct elem *p, const struct elem *q)
{
    if (q->cmp_type == CMP_BITS)
        return bit_cmp(p, q);
        
    return byte_cmp(p, q);
}

KAVL_INIT(my, struct elem, head, scmp)


struct mphdr *mem_pool(bool is_static)
{
    struct mphdr *hdr = calloc(sizeof(struct mphdr), 1);
    if (hdr) {
        hdr->static_data = is_static;
    }
    return hdr;
}


struct elem *mem_get(const struct mphdr *hdr, const char *str, int len)
{
    struct {
        int len;
        const char *data;
    } temp = { .len = len, .data = str };
    
    return kavl_find(my, hdr->root, (struct elem *)&temp, 0);
}


struct elem *mem_add(struct mphdr *hdr, char *str, int len, size_t struct_size)
{
    struct elem *v, *e = calloc(struct_size, 1);
    if (!e) {
        return 0;
    }
    e->len = len;
    while (1) {
        if (!hdr->static_data) {
            e->data = malloc(len);
            if (!e->data) {
                break;
            }
            memcpy(e->data, str, len);
        }
        else {
            e->data = str;
        }
        v = kavl_insert(my, &hdr->root, e, 0);
        if (e != v) {
            if (!hdr->static_data)
                free(e->data);
            break;
        }
        return v;
    }
    free(e);
    return 0;
}


void mem_delete(struct mphdr *hdr, const char *str, int len)
{
    struct {
        int len;
        const char *data;
    } temp = { .len = len, .data = str };
    
    struct elem *e = kavl_erase(my, &hdr->root, (struct elem *)&temp, 0);
    if (!e) {
        return;
    }
    if (!hdr->static_data) {
        free(e->data);
        e->data = 0;
    }
    free(e);
}


void mem_destroy(struct mphdr *hdr)
{
    while (hdr->root) {
        struct elem *e = kavl_erase_first(my, &hdr->root);
        if (!e) {
            break;
        }
        if (!hdr->static_data) {
            free(e->data);
        }
        e->data = 0;
        free(e);
    }
    free(hdr);
}
