#ifndef MPOOL_H
#define MPOOL_H

#include <stdbool.h>
#include <time.h>
#include "kavl.h"

struct elem {
    int len;
    char *data;
    int m;
    time_t time;
    KAVL_HEAD(struct elem) head;
};

struct mphdr {
    bool stat;
    struct elem *root;
};

struct mphdr *mem_pool(bool cst);

struct elem *mem_get(struct mphdr *hdr, char *str, int len);

struct elem *mem_add(struct mphdr *hdr, char *str, int len);

void mem_delete(struct mphdr *hdr, char *str, int len);

void mem_destroy(struct mphdr *hdr);

#endif
