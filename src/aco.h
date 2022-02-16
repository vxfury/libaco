#ifndef ACO_H
#define ACO_H

#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <pthread.h>

#ifdef ACO_USE_VALGRIND
    #include <valgrind/valgrind.h>
#endif

#define aco_likely(x) (__builtin_expect(!!(x), 1))

#define aco_unlikely(x) (__builtin_expect(!!(x), 0))

#define aco_assert(EX) ((aco_likely(EX)) ? ((void)0) : (abort()))

#define aco_log_always(fmt, ...)                                                                        \
    do {                                                                                                \
        struct tm lctime;                                                                               \
        struct timeval tv;                                                                              \
        gettimeofday(&tv, NULL);                                                                        \
        localtime_r(&tv.tv_sec, &lctime);                                                               \
        printf("<%d,%d,%d> \033[2;3m%02d/%02d %02d:%02d:%02d.%03d\033[0m " fmt "\n", aco_getpid(),      \
               aco_gettid(), aco_getrid(), lctime.tm_mon + 1, lctime.tm_mday, lctime.tm_hour,           \
               lctime.tm_min, lctime.tm_sec, (int)(((tv.tv_usec + 500) / 1000) % 1000), ##__VA_ARGS__); \
    } while (0)

#if defined(aco_attr_no_asan)
    #error "aco_attr_no_asan already defined"
#endif
#if defined(ACO_USE_ASAN)
    #if defined(__has_feature)
        #if __has_feature(__address_sanitizer__)
            #define aco_attr_no_asan __attribute__((__no_sanitize_address__))
        #endif
    #endif
    #if defined(__SANITIZE_ADDRESS__) && !defined(aco_attr_no_asan)
        #define aco_attr_no_asan __attribute__((__no_sanitize_address__))
    #endif
#endif
#ifndef aco_attr_no_asan
    #define aco_attr_no_asan
#endif

#if defined(__cplusplus) || (defined(_MSC_VER) && !defined(__clang__))
    #define aco_static_assert(cond, msg) static_assert(cond, msg)
#else
    #define aco_static_assert(cond, msg) _Static_assert(cond, msg)
#endif

#if defined(__i386__) || defined(_M_IX86)
    #define ACO_REG_IDX_RETADDR 0
    #define ACO_REG_IDX_SP      1
    #define ACO_REG_IDX_BP      2
    #define ACO_REG_IDX_FPU     6
    #ifdef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        #define ACO_REG_IDX_MAX 6
    #else
        #define ACO_REG_IDX_MAX 8
    #endif
#elif defined(__x86_64__) || defined(_M_X64)
    #define ACO_REG_IDX_RETADDR 4
    #define ACO_REG_IDX_SP      5
    #define ACO_REG_IDX_BP      7
    #define ACO_REG_IDX_FPU     8
    #ifdef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        #define ACO_REG_IDX_MAX 8
    #else
        #define ACO_REG_IDX_MAX 9
    #endif
#elif defined(__aarch64__)
    #define ACO_REG_IDX_RETADDR 13
    #define ACO_REG_IDX_SP      14
    #define ACO_REG_IDX_BP      12
    #define ACO_REG_IDX_FPU     15
    #ifdef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        #define ACO_REG_IDX_MAX 15
    #else
        #define ACO_REG_IDX_MAX 16
    #endif
#else
    #error "platform no support yet"
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef struct aco_st aco_t;

typedef struct {
    void *ptr;
    size_t sz;
    size_t valid_sz;
    // max copy size in bytes
    size_t max_cpsz;
    // copy from share stack to this save stack
    size_t ct_save;
    // copy from this save stack to share stack
    size_t ct_restore;
} aco_save_stack_t;

typedef struct {
    void *ptr;
    size_t sz;
    void *align_highptr;
    void *align_retptr;
    size_t align_validsz;
    size_t align_limit;
    aco_t *owner;

    void *guard_page_ptr;
    size_t guard_page_size;

#ifdef ACO_USE_VALGRIND
    unsigned long valgrind_stk_id;
#endif
} aco_share_stack_t;

typedef void (*aco_routine_f)(void);
typedef void *aco_routine_arg_t;

struct aco_st {
    void *reg[ACO_REG_IDX_MAX]; /* cpu registers' state, MUST be first member */

    aco_routine_f fp;
    aco_routine_arg_t arg;

    aco_t *main_co;
    unsigned int has_bits[1];

    aco_save_stack_t save_stack;
    aco_share_stack_t *share_stack;

    struct envlist {
        size_t size;
        struct env {
            char *name;
            char *value;
        } * pairs;
    } * enviros;
    struct speclist {
        size_t size;
        void **values;
    } * specifics;

    struct {
        size_t size;
        void **values;
    } plugins;
};

/* coroutine: options */
#define ACO_BITSIZE (sizeof(unsigned int) * 8)
#define ACO_DEFINE_BOOLEAN(BIT, chk, set, clr)              \
    static inline bool aco_##chk(const aco_t *co)           \
    {                                                       \
        static const unsigned int nw = (BIT) / ACO_BITSIZE; \
        static const unsigned int nb = (BIT) % ACO_BITSIZE; \
        if (co != NULL) {                                   \
            return (co->has_bits[nw] & (0x1 << nb)) != 0;   \
        } else {                                            \
            return false;                                   \
        }                                                   \
    }                                                       \
    static inline void aco_##set(aco_t *co)                 \
    {                                                       \
        static const unsigned int nw = (BIT) / ACO_BITSIZE; \
        static const unsigned int nb = (BIT) % ACO_BITSIZE; \
        if (co != NULL) {                                   \
            co->has_bits[nw] |= 01 << nb;                   \
        }                                                   \
    }                                                       \
    static inline void aco_##clr(aco_t *co)                 \
    {                                                       \
        static const unsigned int nw = (BIT) / ACO_BITSIZE; \
        static const unsigned int nb = (BIT) % ACO_BITSIZE; \
        if (co != NULL) {                                   \
            co->has_bits[nw] &= ~(01 << nb);                \
        }                                                   \
    }

ACO_DEFINE_BOOLEAN(0, is_end, set_end, clr_end)
ACO_DEFINE_BOOLEAN(1, syscall_hooked, syscall_hook, syscall_unhook)
ACO_DEFINE_BOOLEAN(2, logcache, logcache_on, logcache_off)


aco_t *aco_self(void);

pid_t aco_getpid(void);
pid_t aco_gettid(void);
pid_t aco_getrid(void);

void aco_funcp_protector(void);
void *acosw(aco_t *from_co, aco_t *to_co) __asm__("acosw");

void aco_thread_init(void (*last_word_co_fp)(void));

/* coroutine */
aco_t *aco_create(aco_t *main_co, aco_share_stack_t *share_stack, size_t save_stack_sz, void (*fp)(void),
                  void *arg);

aco_attr_no_asan void aco_resume(aco_t *resume_co);

aco_attr_no_asan void aco_yield_to(aco_t *resume_co);

void aco_destroy(aco_t *co);

static inline void aco_yield(void)
{
    aco_t *co = aco_self();
    aco_assert(co != NULL);
    acosw(co, co->main_co);
}

static inline void aco_exit(void)
{
    aco_t *co = aco_self();
    aco_set_end(co);
    aco_assert(co->share_stack->owner == co);
    co->share_stack->owner = NULL;
    co->share_stack->align_validsz = 0;
    acosw(co, co->main_co);
    aco_assert(0);
}

static inline void *aco_get_arg(void)
{
    return aco_self()->arg;
}

static inline bool aco_is_main_co(aco_t *co)
{
    return co->main_co == NULL;
}

/* share stack */
aco_share_stack_t *aco_share_stack_new(size_t sz, bool enable_guard_page);
void aco_share_stack_destroy(aco_share_stack_t *sstk);

/* coroutine: specific */
void *aco_getspecific(pthread_key_t key);
int aco_setspecific(pthread_key_t key, const void *value);

#ifdef __cplusplus
}
#endif

#endif
