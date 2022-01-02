#ifndef ACO_INNER_H
#define ACO_INNER_H

#include "aco.h"

struct aco_cond_t;

class aco_mutex {
  public:
    aco_mutex()
    {
        // m_ptCondSignal = co_cond_alloc();
        m_iWaitItemCnt = 0;
    }

    ~aco_mutex()
    {
        // co_cond_free(m_ptCondSignal);
    }

    void lock()
    {
        if (m_iWaitItemCnt > 0) {
            m_iWaitItemCnt++;
            // co_cond_timedwait(m_ptCondSignal, -1);
        } else {
            m_iWaitItemCnt++;
        }
    }
    void unlock()
    {
        m_iWaitItemCnt--;
        // co_cond_signal(m_ptCondSignal);
    }

  private:
    // aco_cond_t *m_ptCondSignal;
    int m_iWaitItemCnt;
};

class aco_lock_guard {
  public:
    aco_lock_guard(aco_mutex *m)
    {
        m_mutex = m;
        m_mutex->lock();
    }

    ~aco_lock_guard()
    {
        m_mutex->unlock();
    }

  private:
    aco_mutex *m_mutex;
};

#if 0
struct stCoRoutineEnv_t;
struct stCoSpec_t {
    void *value;
};

struct stStackMem_t {
    stCoRoutine_t *occupy_co;
    int stack_size;
    char *stack_bp; // stack_buffer + stack_size
    char *stack_buffer;
};

struct stShareStack_t {
    unsigned int alloc_idx;
    int stack_size;
    int count;
    stStackMem_t **stack_array;
};

struct stCoRoutine_t {
    stCoRoutineEnv_t *env;
    pfn_co_routine_t pfn;
    void *arg;
    coctx_t ctx;

    char cStart;
    char cEnd;
    char cIsMain;
    char cEnableSysHook;
    char cIsShareStack;

    void *pvEnv;

    // char sRunStack[ 1024 * 128 ];
    stStackMem_t *stack_mem;


    // save satck buffer while confilct on same stack_buffer;
    char *stack_sp;
    unsigned int save_size;
    char *save_buffer;

    stCoSpec_t aSpec[1024];
};



// 1.env
void co_init_curr_thread_env();
stCoRoutineEnv_t *co_get_curr_thread_env();

// 2.coroutine
void co_free(stCoRoutine_t *co);
void co_yield_env(stCoRoutineEnv_t *env);

// 3.func



//-----------------------------------------------------------------------------------------------

struct stTimeout_t;
struct stTimeoutItem_t;

stTimeout_t *AllocTimeout(int iSize);
void FreeTimeout(stTimeout_t *apTimeout);
int AddTimeout(stTimeout_t *apTimeout, stTimeoutItem_t *apItem, uint64_t allNow);

struct stCoEpoll_t;
stCoEpoll_t *AllocEpoll();
void FreeEpoll(stCoEpoll_t *ctx);

stCoRoutine_t *GetCurrThreadCo();
void SetEpoll(stCoRoutineEnv_t *env, stCoEpoll_t *ev);

typedef void (*pfnCoRoutineFunc_t)();
#endif

#endif
