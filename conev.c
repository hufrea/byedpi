#define CONEV_H
#include <conev.h>

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>


struct poolhd *init_pool(int count)
{
    struct poolhd *pool = malloc(sizeof(struct poolhd));
    if (!pool) {
        return 0;
    }
    pool->max = count;
    pool->count = 0;
    
    #ifndef NOEPOLL
    int efd = epoll_create(count);
    if (efd < 0) {
        perror("epoll_create");
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
    return pool;
}


struct eval *add_event(struct poolhd *pool, enum eid type,
        int fd, int e)
{
    if (pool->count >= pool->max)
        return 0;
    struct eval *val = pool->links[pool->count];
    
    val->fd = fd;
    val->index = pool->count;
    val->type = type;
    val->pair = 0;
    val->tmpbuf = 0;
    val->size = 0;
    val->offset = 0;
    val->flag = 0;
    
    #ifndef NOEPOLL
    struct epoll_event ev = {
        EPOLLIN | EPOLLERR | EPOLLRDHUP | e, {val}
    };
    if (epoll_ctl(pool->efd, EPOLL_CTL_ADD, fd, &ev)) {
        return 0;
    }
    val->events = ev.events;
    #else
    struct pollfd *pfd = &(pool->pevents[pool->count]);
    
    pfd->fd = fd;
    pfd->events = POLLIN | POLLERR | POLLRDHUP | e;
    pfd->revents = 0;
    #endif
    
    pool->count++;
    return val;
}


void del_event(struct poolhd *pool, struct eval *val) 
{
    if (!val->fd) {
        return;
    }
    if (val->tmpbuf) {
        free(val->tmpbuf);
        val->tmpbuf = 0;
    }
    close(val->fd);
    val->fd = 0;
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
        if (val->pair == val) {
            val->pair->pair = 0;
        }
        del_event(pool, val->pair);
        val->pair = 0;
    }
}


void destroy_pool(struct poolhd *pool)
{
    for (int x = 0; x < pool->count; x++) {
        struct eval *val = pool->links[x];
        if (val->fd) {
            close(val->fd);
        }
        if (val->tmpbuf) {
            free(val->tmpbuf);
            val->tmpbuf = 0;
        }
    }
    if (pool->items) {
        free(pool->items);
    }
    if (pool->links) {
        free(pool->links);
    }
    if (pool->pevents) {
        free(pool->pevents);
    }
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
    int i = *offs;
    if (i < 0) {
        i = (epoll_wait(pool->efd, pool->pevents, pool->max, -1) - 1);
        if (i < 0) {
            perror("epoll_wait");
            return 0;
        }
    }
    *offs = i - 1;
    *type = pool->pevents[i].events;
    return pool->pevents[i].data.ptr;
}


int mod_etype(struct poolhd *pool, struct eval *val, int type, char add)
{
    struct epoll_event ev = {
        .events = val->events, .data = {val}
    };
    if (add)
       ev.events |= type;
    else
       ev.events &= ~type;
    val->events = ev.events;
    int s = epoll_ctl(pool->efd, EPOLL_CTL_MOD, val->fd, &ev);
    if (s)
        perror("epoll_ctl");
    return s;
}

#else
struct eval *next_event(struct poolhd *pool, int *offs, int *typel)
{
    for (int i = *offs; ; i--) {
        if (i < 0) {
            if (poll(pool->pevents, pool->count, -1) <= 0) {
                perror("poll");
                return 0;
            }
            i = pool->count - 1;
        }
        short type = pool->pevents[i].revents;
        if (!type)
            continue;
            
        pool->pevents[i].revents = 0;
        *offs = i - 1;
        *typel = type;
        return pool->links[i];
    }
}


int mod_etype(struct poolhd *pool, struct eval *val, int type, char add)
{
   int index = val->index;
   if (add)
       pool->pevents[index].events |= type;
   else
       pool->pevents[index].events &= ~type;
   return 0;
}
#endif