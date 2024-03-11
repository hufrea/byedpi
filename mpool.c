#include <stdlib.h>
#include <string.h>
#include <mpool.h>


struct mphdr *mem_pool(int count)
{
    struct mphdr *hdr = malloc(sizeof(struct mphdr));
    if (!hdr) {
        return 0;
    }
    hdr->inc = count;
    hdr->max = count;
    hdr->count = 0;
    
    hdr->values = malloc(sizeof(*hdr->values) * count);
    if (!hdr->values) {
        free(hdr);
        hdr = 0;
    }
    return hdr;
}


int mem_index(struct mphdr *hdr, char *str, int len)
{
    if (!hdr->count) {
        return -2;
    }
    int s = 0, m, i;
    int e = hdr->count - 1;
    
    while (s <= e) {
        m = s + (e - s) / 2;
        
        struct elem *val = hdr->values[m];
        if (val->len != len)
            i = len < val->len ? -1 : 1;
        else
            i = memcmp(str, val->data, len);
        
        if (i > 0)
            s = m + 1;
        else if (i < 0)
            e = m - 1;
        else
            return m;
    }
    return -(m + 2 + (i > 0 ? 1 : 0));
}


struct elem *mem_add(struct mphdr *hdr, char *str, int len, int pos)
{
    int max = hdr->max;
    
    if (hdr->count >= max) {
        max += hdr->inc;
        struct elem **new = realloc(hdr->values, sizeof(*hdr->values) * max);
        if (!new) {
            return 0;
        }
        hdr->max = max;
        hdr->values = new;
    }
    if (pos >= 0) {
        return hdr->values[pos];
    }
    pos = -pos - 2;
    
    struct elem *val = malloc(sizeof(struct elem) + len);
    if (!val) {
        return 0;
    }
    memset(val, 0, sizeof(*val));
    memcpy(val->data, str, len);
    val->len = len;
    
    if (pos < hdr->count) {
        void *p = &hdr->values[pos];
        void *n = &hdr->values[pos + 1];
        void *e = &hdr->values[hdr->count];
        memmove(n, p, e - p);
    }
    hdr->values[pos] = val;
    hdr->count++;
    return val;
}


void mem_delete(struct mphdr *hdr, int pos)
{
    int max = hdr->max;
    if (!hdr->count) {
        return;
    }
    if (max > hdr->inc && 
            (max - hdr->count) > hdr->inc * 2) {
        max -= hdr->inc;
        struct elem **new = realloc(hdr->values, sizeof(*hdr->values) * max);
        if (new) {
            hdr->max = max;
            hdr->values = new;
        }
    }
    free(hdr->values[pos]);
    
    if (pos < hdr->count) {
        void *p = &hdr->values[pos];
        void *n = &hdr->values[pos + 1];
        void *e = &hdr->values[hdr->count];
        memmove(p, n, e - n);
    }
    hdr->count--;
}
