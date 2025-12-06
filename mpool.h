#ifndef MPOOL_H
#define MPOOL_H

#include <stdbool.h>
#include <time.h>

#include "kavl.h"
#include "params.h"

#define CMP_BYTES 0
#define CMP_BITS 1
#define CMP_HOST 2

#define MF_STATIC 1
#define MF_EXTRA 2

#pragma pack(push, 1)

struct cache_key {
    uint16_t family;
    uint16_t port;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } ip;
};

#pragma pack(pop)

struct elem {
    int len;
    char *data;
    unsigned char cmp_type;
    KAVL_HEAD(struct elem) head;
};

struct elem_ex {
    struct elem main;
    unsigned int extra_len;
    char *extra;
};

struct elem_i {
    struct elem main;
    unsigned int extra_len;
    char *extra;
    
    uint64_t dp_mask;
    int detect;
    time_t time;
    int time_inc;
};

struct mphdr {
    unsigned short flags;
    unsigned char cmp_type;
    size_t count;
    struct elem *root;
};

struct mphdr *mem_pool(unsigned short flags, unsigned char cmp_type);

void *mem_get(const struct mphdr *hdr, const char *str, int len);

void *mem_add(struct mphdr *hdr, char *str, int len, size_t ssize);

void mem_delete(struct mphdr *hdr, const char *str, int len);

void mem_destroy(struct mphdr *hdr);

void dump_cache(struct mphdr *hdr, FILE *out);

void load_cache(struct mphdr *hdr, FILE *in);

#endif
