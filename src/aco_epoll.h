#ifndef ACO_EPOLL_H
#define ACO_EPOLL_H

#include <stdint.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <time.h>

#if !defined(__APPLE__) && !defined(__FreeBSD__)

#include <sys/epoll.h>

struct aco_epoll_res {
    int size;
    struct epoll_event *events;
    struct kevent *eventlist;
};

#else
#include <sys/event.h>

#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3

enum EPOLL_EVENTS {
    EPOLLIN = 0X001,
    EPOLLPRI = 0X002,
    EPOLLOUT = 0X004,

    EPOLLERR = 0X008,
    EPOLLHUP = 0X010,

    EPOLLRDNORM = 0x40,
    EPOLLWRNORM = 0x004,
};

struct epoll_event {
    uint32_t events;
    union {
        void *ptr;
        int fd;
        uint32_t u32;
        uint64_t u64;
    } data;
};

struct aco_epoll_res {
    int size;
    struct epoll_event *events;
    struct kevent *eventlist;
};

#endif

int aco_epoll_wait(int epfd, struct aco_epoll_res *events, int maxevents, int timeout);
int aco_epoll_ctl(int epfd, int op, int fd, struct epoll_event *);
int aco_epoll_create(int size);
struct aco_epoll_res *aco_epoll_res_alloc(int n);
void aco_epoll_res_free(struct aco_epoll_res *);

#endif
