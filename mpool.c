#include "mpool.h"

#include <stdlib.h>
#include <string.h>


static inline int scmp(const struct elem *p, const struct elem *q)
{
    if (p->len != q ->len) {
        return p->len < q->len ? -1 : 1;
    }
    return memcmp(p->data, q->data, p->len);
}
    
KAVL_INIT(my, struct elem, head, scmp)


struct mphdr *mem_pool(bool cst)
{
    struct mphdr *hdr = calloc(sizeof(struct mphdr), 1);
    if (hdr) {
        hdr->stat = cst;
    }
    return hdr;
}


struct elem *mem_get(struct mphdr *hdr, char *str, int len)
{
    struct {
        int len;
        char *data;
    } temp = { .len = len, .data = str };
    
    return kavl_find(my, hdr->root, (struct elem *)&temp, 0);
}


struct elem *mem_add(struct mphdr *hdr, char *str, int len)
{
    struct elem *v, *e = calloc(sizeof(struct elem), 1);
    if (!e) {
        return 0;
    }
    e->len = len;
    if (!hdr->stat) {
        e->data = malloc(len);
        if (!e->data) {
            free(e);
            return 0;
        }
        memcpy(e->data, str, len);
    }
    else {
        e->data = str;
    }
    v = kavl_insert(my, &hdr->root, e, 0);
    if (e != v) {
        if (!hdr->stat) {
            free(e->data);
        }
        free(e);
    }
    return v;
}


void mem_delete(struct mphdr *hdr, char *str, int len)
{
    struct {
        int len;
        char *data;
    } temp = { .len = len, .data = str };
    
    struct elem *e = kavl_erase(my, &hdr->root, (struct elem *)&temp, 0);
    if (!e) {
        return;
    }
    if (!hdr->stat) {
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
        if (!hdr->stat && e->data) {
            free(e->data);
        }
        e->data = 0;
        free(e);
    }
    free(hdr);
}
