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
#include <sys/mman.h>
#include <pthread.h>

#ifdef ACO_USE_VALGRIND
#include <valgrind/valgrind.h>
#endif

#define aco_likely(x) (__builtin_expect(!!(x), 1))

#define aco_unlikely(x) (__builtin_expect(!!(x), 0))

#define aco_assert(EX) ((aco_likely(EX)) ? ((void)0) : (abort()))

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

#ifdef __cplusplus
extern "C" {
#endif

#define ACO_VERSION_MAJOR 1
#define ACO_VERSION_MINOR 2
#define ACO_VERSION_PATCH 4

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

struct aco_s;
typedef struct aco_s aco_t;

typedef struct {
    void *ptr;
    size_t sz;
    void *align_highptr;
    void *align_retptr;
    size_t align_validsz;
    size_t align_limit;
    aco_t *owner;

    char guard_page_enabled;
    void *real_ptr;
    size_t real_sz;

#ifdef ACO_USE_VALGRIND
    unsigned long valgrind_stk_id;
#endif
} aco_share_stack_t;

typedef void (*aco_cofuncp_t)(void);

struct aco_env;

struct aco_s {
    // cpu registers' state
    void *reg[ACO_REG_IDX_MAX];
    aco_t *main_co;
    void *arg;
    char is_end;

    aco_cofuncp_t fp;

    bool hook_syscall;
    struct aco_env *env;
    aco_save_stack_t save_stack;
    aco_share_stack_t *share_stack;

    struct {
        void *value;
    } specifics[1024];
};

extern void aco_thread_init(aco_cofuncp_t last_word_co_fp);

extern void *acosw(aco_t *from_co, aco_t *to_co) __asm__("acosw"); // asm

extern void aco_save_fpucw_mxcsr(void *p) __asm__("aco_save_fpucw_mxcsr"); // asm

extern void aco_funcp_protector_asm(void) __asm__("aco_funcp_protector_asm"); // asm

extern void aco_funcp_protector(void);

extern aco_share_stack_t *aco_share_stack_new(size_t sz);

aco_share_stack_t *aco_share_stack_new2(size_t sz, char guard_page_enabled);

extern void aco_share_stack_destroy(aco_share_stack_t *sstk);

extern aco_t *aco_create(aco_t *main_co, aco_share_stack_t *share_stack, size_t save_stack_sz, aco_cofuncp_t fp,
                         void *arg);

// aco's Global Thread Local Storage variable `co`
extern __thread aco_t *aco_gtls_co;

aco_attr_no_asan extern void aco_resume(aco_t *resume_co);

aco_attr_no_asan extern void aco_yield_to(aco_t *resume_co);

// extern void aco_yield1(aco_t* yield_co);
#define aco_yield1(yield_co)                    \
    do {                                        \
        aco_assert(yield_co != NULL);           \
        aco_assert(yield_co != NULL);           \
        acosw((yield_co), (yield_co)->main_co); \
    } while (0)

#define aco_yield()              \
    do {                         \
        aco_yield1(aco_gtls_co); \
    } while (0)

#define aco_get_arg() (aco_gtls_co->arg)

#define aco_get_co() \
    ({               \
        (void)0;     \
        aco_gtls_co; \
    })

#define aco_co()     \
    ({               \
        (void)0;     \
        aco_gtls_co; \
    })

extern void aco_destroy(aco_t *co);

#define aco_is_main_co(co) ({ ((co)->main_co) == NULL; })

#define aco_exit1(co)                                 \
    do {                                              \
        (co)->is_end = 1;                             \
        aco_assert((co)->share_stack->owner == (co)); \
        (co)->share_stack->owner = NULL;              \
        (co)->share_stack->align_validsz = 0;         \
        aco_yield1((co));                             \
        aco_assert(0);                                \
    } while (0)

#define aco_exit()              \
    do {                        \
        aco_exit1(aco_gtls_co); \
    } while (0)


void aco_syscall_hook();
void aco_syscall_unhook();
bool aco_syscall_hooked();

void *aco_getspecific(pthread_key_t key);
int aco_setspecific(pthread_key_t key, const void *value);

#ifdef __cplusplus
}
#endif

#endif
