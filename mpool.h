#ifndef MPOOL_H
#define MPOOL_H

#include <stdbool.h>
#include <time.h>
#include "kavl.h"

#define CMP_BYTES 0
#define CMP_BITS 1
#define CMP_HOST 2

struct elem {
    int len;
    char *data;
    unsigned char cmp_type;
    KAVL_HEAD(struct elem) head;
};

struct elem_i {
    struct elem i;
    int m;
    time_t time;
};

struct mphdr {
    bool static_data;
    unsigned char cmp_type;
    size_t count;
    struct elem *root;
};

struct mphdr *mem_pool(bool is_static, unsigned char cmp_type);

struct elem *mem_get(const struct mphdr *hdr, const char *str, int len);

struct elem *mem_add(struct mphdr *hdr, char *str, int len, size_t ssize);

void mem_delete(struct mphdr *hdr, const char *str, int len);

void mem_destroy(struct mphdr *hdr);

#endif
