#include "aco.h"
#include "aco_sync.h"

using namespace async;

void aco_cond::notify_one(void)
{
    timer_event *ev = slot.pop_event();
    if (!ev) {
        return;
    }
}

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
