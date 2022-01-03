#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "aco.h"
#include "aco_epoll.h"

#if !defined(__APPLE__) && !defined(__FreeBSD__)

int aco_epoll_wait(int epfd, struct aco_epoll_res *events, int maxevents, int timeout)
{
    return epoll_wait(epfd, events->events, maxevents, timeout);
}

int aco_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev)
{
    return epoll_ctl(epfd, op, fd, ev);
}

int aco_epoll_create(int size)
{
    return epoll_create(size);
}

struct aco_epoll_res *aco_epoll_res_alloc(int n)
{
    struct aco_epoll_res *ptr = (struct aco_epoll_res *)malloc(sizeof(struct aco_epoll_res));

    ptr->size = n;
    ptr->events = (struct epoll_event *)calloc(1, n * sizeof(struct epoll_event));

    return ptr;
}

void aco_epoll_res_free(struct aco_epoll_res *ptr)
{
    if (!ptr) return;
    if (ptr->events) free(ptr->events);
    free(ptr);
}

#else

class fd_map // million of fd , 1024 * 1024
{
  public:
    fd_map()
    {
        memset(m_pp, 0, sizeof(m_pp));
    }
    ~fd_map()
    {
        for (size_t i = 0; i < sizeof(m_pp) / sizeof(m_pp[0]); i++) {
            if (m_pp[i]) {
                free(m_pp[i]);
                m_pp[i] = NULL;
            }
        }
    }
    inline int clear(int fd)
    {
        set(fd, NULL);
        return 0;
    }

    inline int set(int fd, const void *ptr)
    {
        int idx = fd / row_size;
        if (idx < 0 || idx >= (int)(sizeof(m_pp) / sizeof(m_pp[0]))) {
            assert(__LINE__ == 0);
            return -__LINE__;
        }
        if (!m_pp[idx]) {
            m_pp[idx] = (void **)calloc(1, sizeof(void *) * col_size);
        }
        m_pp[idx][fd % col_size] = (void *)ptr;
        return 0;
    }
    inline void *get(int fd)
    {
        int idx = fd / row_size;
        if (idx < 0 || idx >= (int)(sizeof(m_pp) / sizeof(m_pp[0]))) {
            return NULL;
        }
        void **lp = m_pp[idx];
        if (!lp) return NULL;

        return lp[fd % col_size];
    }

  private:
    static const int row_size = 1024;
    static const int col_size = 1024;

    void **m_pp[1024];
};
__thread fd_map *s_fd_map = NULL;

static inline fd_map *get_fd_map()
{
    if (!s_fd_map) {
        s_fd_map = new fd_map();
    }
    return s_fd_map;
}

struct kevent_pair_t {
    int fire_idx;
    int events;
    uint64_t u64;
};

int aco_epoll_create(int /*size*/)
{
    return kqueue();
}

int aco_epoll_wait(int epfd, struct aco_epoll_res *events, int maxevents, int timeout)
{
    struct timespec t = {0};
    if (timeout > 0) {
        t.tv_sec = timeout;
    }
    int ret = kevent(epfd, NULL, 0,                // register null
                     events->eventlist, maxevents, // just retrival
                     (-1 == timeout) ? NULL : &t);
    int j = 0;
    for (int i = 0; i < ret; i++) {
        struct kevent &kev = events->eventlist[i];
        struct kevent_pair_t *ptr = (struct kevent_pair_t *)kev.udata;
        struct epoll_event *ev = events->events + i;
        if (0 == ptr->fire_idx) {
            ptr->fire_idx = i + 1;
            memset(ev, 0, sizeof(*ev));
            ++j;
        } else {
            ev = events->events + ptr->fire_idx - 1;
        }
        if (EVFILT_READ == kev.filter) {
            ev->events |= EPOLLIN;
        } else if (EVFILT_WRITE == kev.filter) {
            ev->events |= EPOLLOUT;
        }
        ev->data.u64 = ptr->u64;
    }
    for (int i = 0; i < ret; i++) {
        ((struct kevent_pair_t *)(events->eventlist[i].udata))->fire_idx = 0;
    }
    return j;
}

int aco_epoll_del(int epfd, int fd)
{
    struct timespec t = {0};
    struct kevent_pair_t *ptr = (struct kevent_pair_t *)get_fd_map()->get(fd);
    if (!ptr) return 0;
    if (EPOLLIN & ptr->events) {
        struct kevent kev = {0};
        kev.ident = fd;
        kev.filter = EVFILT_READ;
        kev.flags = EV_DELETE;
        kevent(epfd, &kev, 1, NULL, 0, &t);
    }
    if (EPOLLOUT & ptr->events) {
        struct kevent kev = {0};
        kev.ident = fd;
        kev.filter = EVFILT_WRITE;
        kev.flags = EV_DELETE;
        kevent(epfd, &kev, 1, NULL, 0, &t);
    }
    get_fd_map()->clear(fd);
    free(ptr);

    return 0;
}

int aco_epoll_ctl(int epfd, int op, int fd, struct epoll_event *ev)
{
    if (EPOLL_CTL_DEL == op) {
        return aco_epoll_del(epfd, fd);
    }

    const int flags = (EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLHUP);
    if (ev->events & ~flags) {
        return -1;
    }

    if (EPOLL_CTL_ADD == op && get_fd_map()->get(fd)) {
        errno = EEXIST;
        return -1;
    } else if (EPOLL_CTL_MOD == op && !get_fd_map()->get(fd)) {
        errno = ENOENT;
        return -1;
    }

    struct kevent_pair_t *ptr = (struct kevent_pair_t *)get_fd_map()->get(fd);
    if (!ptr) {
        ptr = (kevent_pair_t *)calloc(1, sizeof(kevent_pair_t));
        get_fd_map()->set(fd, ptr);
    }

    int ret = 0;
    struct timespec t = {0};

    // printf("ptr->events 0x%X\n",ptr->events);

    if (EPOLL_CTL_MOD == op) {
        // 1.delete if exists
        if (ptr->events & EPOLLIN) {
            struct kevent kev = {0};
            EV_SET(&kev, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
            kevent(epfd, &kev, 1, NULL, 0, &t);
        }
        // 1.delete if exists
        if (ptr->events & EPOLLOUT) {
            struct kevent kev = {0};
            EV_SET(&kev, fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
            ret = kevent(epfd, &kev, 1, NULL, 0, &t);
            // printf("delete write ret %d\n",ret );
        }
    }

    do {
        if (ev->events & EPOLLIN) {
            // 2.add
            struct kevent kev = {0};
            EV_SET(&kev, fd, EVFILT_READ, EV_ADD, 0, 0, ptr);
            ret = kevent(epfd, &kev, 1, NULL, 0, &t);
            if (ret) break;
        }
        if (ev->events & EPOLLOUT) {
            // 2.add
            struct kevent kev = {0};
            EV_SET(&kev, fd, EVFILT_WRITE, EV_ADD, 0, 0, ptr);
            ret = kevent(epfd, &kev, 1, NULL, 0, &t);
            if (ret) break;
        }
    } while (0);

    if (ret) {
        get_fd_map()->clear(fd);
        free(ptr);
        return ret;
    }

    ptr->events = ev->events;
    ptr->u64 = ev->data.u64;

    return ret;
}

struct aco_epoll_res *aco_epoll_res_alloc(int n)
{
    struct aco_epoll_res *ptr = (struct aco_epoll_res *)malloc(sizeof(struct aco_epoll_res));

    ptr->size = n;
    ptr->events = (struct epoll_event *)calloc(1, n * sizeof(struct epoll_event));
    ptr->eventlist = (struct kevent *)calloc(1, n * sizeof(struct kevent));

    return ptr;
}

void aco_epoll_res_free(struct aco_epoll_res *ptr)
{
    if (!ptr) return;
    if (ptr->events) free(ptr->events);
    if (ptr->eventlist) free(ptr->eventlist);
    free(ptr);
}

#endif

// co cond

#if 0
struct aco_cond_t;
struct aco_timeout_t {
    int v;
    void *pArg;
};

struct aco_cond_item_t {
    aco_cond_item_t *pPrev;
    aco_cond_item_t *pNext;
    aco_cond_t *pLink;

    aco_timeout_t timeout;
};
struct aco_cond_t {
    aco_cond_item_t *head;
    aco_cond_item_t *tail;
};

static void OnSignalProcessEvent(aco_timeout_t *ap)
{
    aco_t *co = (aco_t *)ap->pArg;
    aco_resume(co);
}

aco_cond_item_t *co_cond_pop(aco_cond_t *link);

int co_cond_signal(aco_cond_t *si)
{
    aco_cond_item_t *sp = co_cond_pop(si);
    if (!sp) {
        return 0;
    }
    RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

    AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);

    return 0;
}

int co_cond_broadcast(aco_cond_t *si)
{
    for (;;) {
        aco_cond_item_t *sp = co_cond_pop(si);
        if (!sp) return 0;

        RemoveFromLink<stTimeoutItem_t, stTimeoutItemLink_t>(&sp->timeout);

        AddTail(co_get_curr_thread_env()->pEpoll->pstActiveList, &sp->timeout);
    }

    return 0;
}

int co_cond_timedwait(aco_cond_t *link, int ms)
{
    aco_cond_item_t *psi = (aco_cond_item_t *)calloc(1, sizeof(aco_cond_item_t));
    psi->timeout.pArg = GetCurrThreadCo();
    psi->timeout.pfnProcess = OnSignalProcessEvent;

    if (ms > 0) {
        unsigned long long now = GetTickMS();
        psi->timeout.ullExpireTime = now + ms;

        int ret = AddTimeout(co_get_curr_thread_env()->pEpoll->pTimeout, &psi->timeout, now);
        if (ret != 0) {
            free(psi);
            return ret;
        }
    }
    AddTail(link, psi);

    co_yield_ct();


    RemoveFromLink<aco_cond_item_t, aco_cond_t>(psi);
    free(psi);

    return 0;
}

aco_cond_t *co_cond_alloc()
{
    return (aco_cond_t *)calloc(1, sizeof(aco_cond_t));
}

int co_cond_free(aco_cond_t *cc)
{
    free(cc);
    return 0;
}

aco_cond_item_t *co_cond_pop(aco_cond_t *link)
{
    aco_cond_item_t *p = link->head;
    if (p) {
        PopHead<aco_cond_item_t, aco_cond_t>(link);
    }
    return p;
}
#endif

struct stTimeoutItemLink_t;
struct stTimeoutItem_t;

#include "aco_time_wheel.h"

struct aco_epoll_t {
    int efd;
    aco_epoll_res *result;
    static const int EPOLL_SIZE = 1024 * 10;

    TimerWheel wheel;

    struct stTimeout_t *pTimeout;
    struct stTimeoutItemLink_t *pstTimeoutList;
    struct stTimeoutItemLink_t *pstActiveList;
};
typedef void (*OnPreparePfn_t)(stTimeoutItem_t *, struct epoll_event &ev, stTimeoutItemLink_t *active);
typedef void (*OnProcessPfn_t)(stTimeoutItem_t *);

aco_epoll_t *aco_epool_new()
{
    aco_epoll_t *ctx = (aco_epoll_t *)calloc(1, sizeof(aco_epoll_t));
    if (ctx != NULL) {
        ctx->efd = aco_epoll_create(aco_epoll_t::EPOLL_SIZE);
        // ctx->pTimeout = AllocTimeout(60 * 1000);
        // ctx->pstActiveList = (stTimeoutItemLink_t *)calloc(1,
        // sizeof(stTimeoutItemLink_t)); ctx->pstTimeoutList =
        // (stTimeoutItemLink_t *)calloc(1, sizeof(stTimeoutItemLink_t));
    }

    return ctx;
}

void aco_epool_del(aco_epoll_t *ctx)
{
    if (ctx != NULL) {
        free(ctx->pstActiveList);
        free(ctx->pstTimeoutList);
        // FreeTimeout(ctx->pTimeout);
        aco_epoll_res_free(ctx->result);
    }
    free(ctx);
}
