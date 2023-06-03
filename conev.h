#include <stdint.h>
#include <netinet/in.h>

#ifndef __linux__
#define NOEPOLL
#endif

#ifndef NOEPOLL
#include <sys/epoll.h>
#define POLLIN EPOLLIN
#define POLLOUT EPOLLOUT
#define POLLERR EPOLLERR
#define POLLHUP EPOLLHUP
#define POLLRDHUP EPOLLRDHUP
#else
#include <sys/poll.h>
#ifndef POLLRDHUP
#define POLLRDHUP POLLHUP
#endif
#endif

enum eid {
    EV_ACCEPT,
    EV_REQUEST,
    EV_CONNECT,
    EV_IGNORE,
    EV_TUNNEL
};

#define FLAG_NOSEND 1
#define FLAG_HTTP 2
#define FLAG_S4 4
#define FLAG_S5 8
#define FLAG_CONN 16

#ifndef CONEV_H
char *eid_name[] = {
    "EV_ACCEPT",
    "EV_REQUEST",
    "EV_CONNECT",
    "EV_IGNORE",
    "EV_TUNNEL"
};
#endif

struct eval {
    int fd;    
    int index;
    enum eid type;
    struct eval *pair;
    size_t send_count;
    int flag;
    #ifndef NOEPOLL
    uint32_t events;
    #endif
};

struct poolhd {
    int max;
    int count;
    int efd;
    struct eval **links;
    struct eval *items;
#ifndef NOEPOLL
    struct epoll_event *pevents;
#else
    struct pollfd *pevents;
#endif
};

struct poolhd *init_pool(int count);

struct eval *add_event(struct poolhd *pool, enum eid type, int fd, int e);

struct eval *add_pair(struct poolhd *pool, struct eval *val, int sfd, int e);

void del_event(struct poolhd *pool, struct eval *val);

void destroy_pool(struct poolhd *pool);

struct eval *next_event(struct poolhd *pool, int *offs, int *type);

int mod_etype(struct poolhd *pool, struct eval *val, int type, char rm);