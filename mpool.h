#ifndef MPOOL_H
#define MPOOL_H

#include <stdbool.h>
#include <time.h>
#include "kavl.h"

struct elem {
    int len;
    char *data;
    KAVL_HEAD(struct elem) head;
};

struct elem_i {
    struct elem i;
    int m;
    time_t time;
};

struct mphdr {
    bool static_data;
    struct elem *root;
};

struct mphdr *mem_pool(bool is_static);

struct elem *mem_get(const struct mphdr *hdr, const char *str, int len);

struct elem *mem_add(struct mphdr *hdr, char *str, int len, size_t ssize);

void mem_delete(struct mphdr *hdr, const char *str, int len);

void mem_destroy(struct mphdr *hdr);

#endif
