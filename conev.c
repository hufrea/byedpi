#include "conev.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <assert.h>


struct poolhd *init_pool(int count)
{
    struct poolhd *pool = calloc(sizeof(struct poolhd), 1);
    if (!pool) {
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
        destroy_pool(pool);
        return 0;
    }
    for (int i = 0; i < count; i++) {
        pool->links[i] = &(pool->items[i]);
    }
    memset(pool->items, 0, sizeof(*pool->items));
    return pool;
}


struct eval *add_event(struct poolhd *pool, enum eid type,
        int fd, int e)
{
    assert(fd > 0);
    if (pool->count >= pool->max) {
        return 0;
    }
    struct eval *val = pool->links[pool->count];
    memset(val, 0, sizeof(*val));
    
    val->mod_iter = pool->iters;
    val->fd = fd;
    val->index = pool->count;
    val->type = type;
    
    #ifndef NOEPOLL
    struct epoll_event ev = { .events = EPOLLRDHUP | e, .data = {val} };
    if (epoll_ctl(pool->efd, EPOLL_CTL_ADD, fd, &ev)) {
        return 0;
    }
    #else
    struct pollfd *pfd = &(pool->pevents[pool->count]);
    
    pfd->fd = fd;
    pfd->events = POLLRDHUP | e;
    pfd->revents = 0;
    #endif
    
    pool->count++;
    return val;
}


void del_event(struct poolhd *pool, struct eval *val) 
{
    assert(val->fd >= -1 && val->mod_iter <= pool->iters);
    if (val->fd == -1) {
        return;
    }
    #ifdef NOEPOLL
    assert(val->fd == pool->pevents[val->index].fd);
    #else
    epoll_ctl(pool->efd, EPOLL_CTL_DEL, val->fd, 0);
    #endif
    if (val->buff.data) {
        assert(val->buff.size);
        free(val->buff.data);
        val->buff.data = 0;
    }
    close(val->fd);
    val->fd = -1;
    val->mod_iter = pool->iters;
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
    assert(pool->count > 0);
}


void destroy_pool(struct poolhd *pool)
{
    for (int x = 0; x < pool->count; x++) {
        struct eval *val = pool->links[x];
        if (val->fd) {
            close(val->fd);
            val->fd = 0;
        }
        if (val->buff.data) {
            free(val->buff.data);
            val->buff.data = 0;
        }
    }
    free(pool->items);
    free(pool->links);
    free(pool->pevents);
    #ifndef NOEPOLL
    if (pool->efd)
        close(pool->efd);
    #endif
    memset(pool, 0, sizeof(*pool));
    free(pool);
}


#ifndef NOEPOLL
struct eval *next_event(struct poolhd *pool, int *offs, int *type)
{
    while (1) {
        int i = *offs;
        assert(i >= -1 && i < pool->max);
        if (i < 0) {
            i = (epoll_wait(pool->efd, pool->pevents, pool->max, -1) - 1);
            if (i < 0) {
                return 0;
            }
            if (pool->iters == UINT_MAX) {
                pool->iters = 0;
            }
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
        .events = EPOLLRDHUP | type, .data = {val}
    };
    return epoll_ctl(pool->efd, EPOLL_CTL_MOD, val->fd, &ev);
}

#else
struct eval *next_event(struct poolhd *pool, int *offs, int *typel)
{
    for (int i = *offs; ; i--) {
        assert(i >= -1 && i < pool->max);
        if (i < 0) {
            if (poll(pool->pevents, pool->count, -1) <= 0) {
                return 0;
            }
            i = pool->count - 1;
            if (pool->iters == UINT_MAX) {
                pool->iters = 0;
            }
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
   pool->pevents[val->index].events = POLLRDHUP | type;
   return 0;
}
#endif
