#include "conev.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include "error.h"


struct poolhd *init_pool(int count)
{
    struct poolhd *pool = calloc(1, sizeof(struct poolhd));
    if (!pool) {
        uniperror("init pool");
        return 0;
    }
    pool->max = count;
    pool->count = 0;
    pool->iters = 0;

    #ifndef NOEPOLL
    int efd = epoll_create(count);
    if (efd < 0) {
        free(pool);
        return 0;
    }
    pool->efd = efd;
    #endif
    pool->pevents = malloc(sizeof(*pool->pevents) * count);
    pool->links = malloc(sizeof(*pool->links) * count);
    pool->items = malloc(sizeof(*pool->items) * count);

    if (!pool->pevents || !pool->links || !pool->items) {
        uniperror("init pool");
        destroy_pool(pool);
        return 0;
    }
    for (int i = 0; i < count; i++) {
        pool->links[i] = &(pool->items[i]);
    }
    memset(pool->items, 0, sizeof(*pool->items));
    return pool;
}


struct eval *add_event(struct poolhd *pool, evcb_t cb,
        int fd, int e)
{
    assert(fd > 0);
    if (pool->count >= pool->max) {
        LOG(LOG_E, "add_event: pool is full\n");
        return 0;
    }
    struct eval *val = pool->links[pool->count];
    memset(val, 0, sizeof(*val));

    val->mod_iter = pool->iters;
    val->fd = fd;
    val->index = pool->count;
    val->cb = cb;

    #ifndef NOEPOLL
    struct epoll_event ev = { .events = _POLLDEF | e, .data = {val} };
    if (epoll_ctl(pool->efd, EPOLL_CTL_ADD, fd, &ev)) {
        uniperror("add event");
        return 0;
    }
    #else
    struct pollfd *pfd = &(pool->pevents[pool->count]);
    
    pfd->fd = fd;
    pfd->events = _POLLDEF | e;
    pfd->revents = 0;
    #endif

    pool->count++;
    return val;
}


void del_event(struct poolhd *pool, struct eval *val) 
{
    assert(val->fd >= -1 && val->mod_iter <= pool->iters);
    LOG(LOG_S, "close: fd=%d (pair=%d), recv: %zd, rounds: %d\n", 
        val->fd, val->pair ? val->pair->fd : -1, 
        val->recv_count, val->round_count);
    if (val->fd == -1) {
        return;
    }
    #ifdef NOEPOLL
    assert(val->fd == pool->pevents[val->index].fd);
    #else
    epoll_ctl(pool->efd, EPOLL_CTL_DEL, val->fd, 0);
    #endif
    if (val->buff) {
        buff_push(pool, val->buff);
        val->buff = 0;
    }
    if (val->sq_buff) {
        buff_push(pool, val->sq_buff);
        val->sq_buff = 0;
    }
    #ifndef _WIN32
    if (val->restore_fake) {
        munmap(val->restore_fake, val->restore_fake_len);
        val->restore_fake = 0;
    }
    #endif
    if (val->host) {
        free(val->host);
        val->host = 0;
    }
    close(val->fd);
    val->fd = -1;
    val->mod_iter = pool->iters;
    remove_timer(pool, val);
    pool->count--;
    
    struct eval *ev = pool->links[pool->count];
    if (ev != val) 
    {
        int index = val->index;
        pool->links[index] = ev;
        pool->links[pool->count] = val;
        #ifdef NOEPOLL
        pool->pevents[index] = pool->pevents[pool->count];
        #endif
        ev->index = index;
    }
    if (val->pair) {
        if (val->pair->pair == val) {
            val->pair->pair = 0;
        }
        struct eval *e = val->pair;
        val->pair = 0;
        del_event(pool, e);
    }
    assert(pool->count >= 0);
}


void destroy_pool(struct poolhd *pool)
{
    while (pool->count) {
        struct eval *val = pool->links[0];
        del_event(pool, val);
    }
    free(pool->items);
    free(pool->links);
    free(pool->pevents);
    #ifndef NOEPOLL
    if (pool->efd)
        close(pool->efd);
    #endif
    buff_destroy(pool->root_buff);
    memset(pool, 0, sizeof(*pool));
    free(pool);
}


#ifndef NOEPOLL
struct eval *next_event(struct poolhd *pool, int *offs, int *type, int ms)
{
    while (1) {
        int i = *offs;
        assert(i >= -1 && i < pool->max);
        if (i < 0) {
            i = epoll_wait(pool->efd, pool->pevents, pool->max, ms);
            if (!i) *type = POLLTIMEOUT;
            if (i <= 0) {
                return 0;
            }
            i--;
            pool->iters++;
        }
        struct eval *val = pool->pevents[i].data.ptr;
        *offs = i - 1;
        if (val->mod_iter == pool->iters) {
            continue;
        }
        *type = pool->pevents[i].events;
        return val;
    }
}


int mod_etype(struct poolhd *pool, struct eval *val, int type)
{
    assert(val->fd > 0);
    struct epoll_event ev = {
        .events = _POLLDEF | type, .data = {val}
    };
    return epoll_ctl(pool->efd, EPOLL_CTL_MOD, val->fd, &ev);
}

#else
struct eval *next_event(struct poolhd *pool, int *offs, int *typel, int ms)
{
    for (int i = *offs; ; i--) {
        assert(i >= -1 && i < pool->max);
        if (i < 0) {
            int ret = poll(pool->pevents, pool->count, ms);
            if (!ret) *typel = POLLTIMEOUT;
            if (ret <= 0) {
                return 0;
            }
            i = pool->count - 1;
            pool->iters++;
        }
        short type = pool->pevents[i].revents;
        if (!type) {
            continue;
        }
        struct eval *val = pool->links[i];
        assert((i < pool->count) || (val->mod_iter == pool->iters));
        if (val->mod_iter == pool->iters) {
            continue;
        }
        pool->pevents[i].revents = 0;
        *offs = i - 1;
        *typel = type;
        return val;
    }
}


int mod_etype(struct poolhd *pool, struct eval *val, int type)
{
   assert(val->index >= 0 && val->index < pool->count);
   pool->pevents[val->index].events = _POLLDEF | type;
   return 0;
}
#endif

static long time_ms(void)
{
    #ifndef _WIN32
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return t.tv_sec * 1e3 + (t.tv_nsec / 1e6);
    #else
    FILETIME st;
    GetSystemTimeAsFileTime(&st);
    return (((((uint64_t)st.dwHighDateTime) << 32) | st.dwLowDateTime) / 1e4);
    #endif
}


void set_timer(struct poolhd *pool, struct eval *val, long ms)
{
    if (val->tv_ms) {
        return;
    }
    struct eval *next = 0, *prev = pool->tv_end;
    val->tv_ms = time_ms() + ms;
    
    while (prev && prev->tv_ms >= val->tv_ms) {
        next = prev;
        prev = prev->tv_prev;
    }
    val->tv_next = next;
    val->tv_prev = prev;
    
    if (next) {
        next->tv_prev = val;
    }
    if (prev) {
        prev->tv_next = val;
    }
    if (!pool->tv_start || next == pool->tv_start) {
        pool->tv_start = val;
    }
    if (!pool->tv_end || prev == pool->tv_end) {
        pool->tv_end = val;
    }
}


void remove_timer(struct poolhd *pool, struct eval *val)
{
    if (val->tv_prev) {
        val->tv_prev->tv_next = val->tv_next;
    }
    if (val->tv_next) {
        val->tv_next->tv_prev = val->tv_prev;
    }
    if (pool->tv_start == val) {
        pool->tv_start = val->tv_next;
    }
    if (pool->tv_end == val) {
        pool->tv_end = val->tv_prev;
    }
    val->tv_ms = 0;
    val->tv_next = 0;
    val->tv_prev = 0;
}


struct eval *next_event_tv(struct poolhd *pool, int *offs, int *type)
{
    if (!pool->tv_start) {
        return next_event(pool, offs, type, -1);
    }
    struct eval *val = 0;
    
    int ms = pool->tv_start->tv_ms - time_ms();
    if (ms > 0) {
        val = next_event(pool, offs, type, ms);
    }
    else *type = POLLTIMEOUT;
    
    if (!val && pool->tv_start && *type == POLLTIMEOUT) {
        val = pool->tv_start;
        remove_timer(pool, val);
    }
    return val;
}


void loop_event(struct poolhd *pool)
{
    int i = -1, etype = -1;
    
    while (!pool->brk) {
        struct eval *val = next_event_tv(pool, &i, &etype);
        if (!val) {
            if (get_e() == EINTR) 
                continue;
            uniperror("(e)poll");
            break;
        }
        LOG(LOG_L, "new event: fd: %d, type: %d\n", val->fd, etype);
        
        int ret = (*val->cb)(pool, val, etype);
        if (ret < 0) {
            del_event(pool, val);
        }
    }
}


struct buffer *buff_pop(struct poolhd *pool, size_t size)
{
    struct buffer *buff = pool->root_buff;  
    if (buff) {
        pool->root_buff = buff->next;
        pool->buff_count--;
    }
    else {
        buff = malloc(sizeof(struct buffer) + size);
        if (!buff) {
            uniperror("malloc");
            return 0;
        }
        LOG(LOG_S, "alloc new buffer\n");
        
        memset(buff, 0, sizeof(struct buffer));
        buff->size = size;
    }
    return buff;
}


void buff_push(struct poolhd *pool, struct buffer *buff)
{
    if (!buff) {
        return;
    }
    if (pool->buff_count >= MAX_BUFF_INP) {
        free(buff);
        return;
    }
    buff->lock = 0;
    buff->offset = 0;
    buff->next = pool->root_buff;
    
    pool->root_buff = buff;
    pool->buff_count++;
}


void buff_destroy(struct buffer *root)
{
    int i = 0;
    for (; root; i++) {
        struct buffer *c = root;
        root = root->next;
        free(c);
    }
    LOG(LOG_S, "buffers count: %d\n", i);
}

