#include <time.h>

struct elem {
    int m;
    time_t time;
    int len;
    char data[];
};
struct mphdr {
    int max;
    int inc;
    int count;
    struct elem **values;
};
struct mphdr *mem_pool(int count);
int mem_index(struct mphdr *hdr, char *str, int len);
struct elem *mem_add(struct mphdr *hdr, char *str, int len, int pos);
void mem_delete(struct mphdr *hdr, int pos);
void mem_destroy(struct mphdr *hdr);