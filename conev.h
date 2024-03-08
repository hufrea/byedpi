#include <stdint.h>

#ifndef __linux__
    #define NOEPOLL
#endif

#ifdef _WIN32
    #include <ws2tcpip.h>
    #define poll(fds, cnt, to) WSAPoll(fds, cnt, to)
    #define close(fd) closesocket(fd)
#else
    #include <netinet/in.h>
    #include <unistd.h>
    
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

#ifndef POLLRDHUP
    #define POLLRDHUP POLLHUP
#endif

enum eid {
    EV_ACCEPT,
    EV_REQUEST,
    EV_CONNECT,
    EV_IGNORE,
    EV_TUNNEL,
    EV_PRE_TUNNEL,
    EV_DESYNC
};

#define FLAG_S4 1
#define FLAG_S5 2
#define FLAG_CONN 4

#ifndef CONEV_H
char *eid_name[] = {
    "EV_ACCEPT",
    "EV_REQUEST",
    "EV_CONNECT",
    "EV_IGNORE",
    "EV_TUNNEL",
    "EV_PRE_TUNNEL",
    "EV_DESYNC"
};
#endif

struct buffer {
    ssize_t size;
    int offset;
    char *data;
};

struct eval {
    int fd;    
    int index;
    enum eid type;
    struct eval *pair;
    struct buffer buff;
    int flag;
    union {
        struct sockaddr_in in;
        struct sockaddr_in6 in6;
    };
    ssize_t recv_count;
    int try_count;
    int saved_m;
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
