#ifndef CONEV_H
#define CONEV_H

#include <stdint.h>
#include <stdbool.h>

#ifndef __linux__
    #define NOEPOLL
#endif

#ifdef _WIN32
    #include <ws2tcpip.h>
    #define poll(fds, cnt, to) WSAPoll(fds, cnt, to)
    #define close(fd) closesocket(fd)
#else
    #include <netinet/in.h>
    #include <sys/socket.h>
    #include <unistd.h>
    #include <time.h>
    
    #ifndef NOEPOLL
        #include <sys/epoll.h>
        #define POLLIN EPOLLIN
        #define POLLOUT EPOLLOUT
        #define POLLERR EPOLLERR
        #define POLLHUP EPOLLHUP
        #define POLLRDHUP EPOLLRDHUP
    #else
        #include <sys/poll.h>
    #endif
#endif

#ifdef __APPLE__
    #define POLLRDHUP POLLHUP
#elif !defined POLLRDHUP
    #define POLLRDHUP 0
#endif
#define POLLTIMEOUT 0

struct poolhd;
struct eval;
typedef int (*evcb_t)(struct poolhd *, struct eval *, int);

union sockaddr_u {
    struct sockaddr sa;
    struct sockaddr_in in;
    struct sockaddr_in6 in6;
};

#define FLAG_S4 1
#define FLAG_S5 2
#define FLAG_CONN 4
#define FLAG_HTTP 8

struct buffer {
    size_t size;
    unsigned int offset;
    ssize_t lock;
    struct buffer *next;
    char data[];
};

struct eval {
    int fd;    
    int index;
    unsigned long long mod_iter;
    evcb_t cb;
    
    long tv_ms;
    struct eval *tv_next, *tv_prev;
    
    struct eval *pair;
    struct buffer *buff, *sq_buff;
    int flag;
    union sockaddr_u addr;
    ssize_t recv_count;
    ssize_t round_sent;
    unsigned int round_count;
    int attempt;
    bool cache;
    bool mark; //
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
    unsigned long long iters;
    bool brk;
    
    struct eval *tv_start, *tv_end;
    struct buffer *root_buff;
};

struct poolhd *init_pool(int count);

struct eval *add_event(struct poolhd *pool, evcb_t cb, int fd, int e);

struct eval *add_pair(struct poolhd *pool, struct eval *val, int sfd, int e);

void del_event(struct poolhd *pool, struct eval *val);

void destroy_pool(struct poolhd *pool);

struct eval *next_event(struct poolhd *pool, int *offs, int *type, int ms);

int mod_etype(struct poolhd *pool, struct eval *val, int type);

void set_timer(struct poolhd *pool, struct eval *val, long ms);

void remove_timer(struct poolhd *pool, struct eval *val);

void loop_event(struct poolhd *pool);

struct buffer *buff_pop(struct poolhd *pool, size_t size);

void buff_push(struct poolhd *pool, struct buffer *buff);

void buff_destroy(struct buffer *root);

static struct buffer *buff_ppop(struct poolhd *pool, size_t size)
{
    struct buffer *b = buff_pop(pool, size);
    if (b) buff_push(pool, b);
    return b;
}
#endif
