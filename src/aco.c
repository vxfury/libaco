#define _GNU_SOURCE

#include "aco.h"
#include <errno.h>
#include <stdio.h>
#include <stdint.h>

/* runtime assertion */
#if defined(__i386__) || defined(_M_IX86)
aco_static_assert(sizeof(void *) == 4, "require 'sizeof(void*) == 4'");
#elif defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
aco_static_assert(sizeof(void *) == 8, "require 'sizeof(void*) == 8'");
aco_static_assert(sizeof(__uint128_t) == 16, "require 'sizeof(__uint128_t) == 16'");
#else
#error "platform no support yet"
#endif
aco_static_assert(sizeof(int) >= 4, "require 'sizeof(int) >= 4'");
aco_static_assert(sizeof(int) <= sizeof(size_t), "require 'sizeof(int) <= sizeof(size_t)'");

// Note: dst and src must be valid address already
#if !defined(aco_memcpy) && (defined(__x86_64__) || defined(_M_X64))
#define aco_amd64_inline_short_aligned_memcpy_test_ok(dst, src, sz)                                                  \
    ((((uintptr_t)(src)&0x0f) == 0) && (((uintptr_t)(dst)&0x0f) == 0) && (((sz)&0x0f) == 0x08) && (((sz) >> 4) >= 0) \
     && (((sz) >> 4) <= 8))

#define aco_amd64_inline_short_aligned_memcpy(dst, src, sz)                                      \
    do {                                                                                         \
        __uint128_t xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7;                              \
        switch ((sz) >> 4) {                                                                     \
            case 0:                                                                              \
                break;                                                                           \
            case 1:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                break;                                                                           \
            case 2:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                break;                                                                           \
            case 3:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                break;                                                                           \
            case 4:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                xmm3 = *((__uint128_t *)(src) + 3);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                break;                                                                           \
            case 5:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                xmm3 = *((__uint128_t *)(src) + 3);                                              \
                xmm4 = *((__uint128_t *)(src) + 4);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                break;                                                                           \
            case 6:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                xmm3 = *((__uint128_t *)(src) + 3);                                              \
                xmm4 = *((__uint128_t *)(src) + 4);                                              \
                xmm5 = *((__uint128_t *)(src) + 5);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                break;                                                                           \
            case 7:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                xmm3 = *((__uint128_t *)(src) + 3);                                              \
                xmm4 = *((__uint128_t *)(src) + 4);                                              \
                xmm5 = *((__uint128_t *)(src) + 5);                                              \
                xmm6 = *((__uint128_t *)(src) + 6);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                *((__uint128_t *)(dst) + 6) = xmm6;                                              \
                break;                                                                           \
            case 8:                                                                              \
                xmm0 = *((__uint128_t *)(src) + 0);                                              \
                xmm1 = *((__uint128_t *)(src) + 1);                                              \
                xmm2 = *((__uint128_t *)(src) + 2);                                              \
                xmm3 = *((__uint128_t *)(src) + 3);                                              \
                xmm4 = *((__uint128_t *)(src) + 4);                                              \
                xmm5 = *((__uint128_t *)(src) + 5);                                              \
                xmm6 = *((__uint128_t *)(src) + 6);                                              \
                xmm7 = *((__uint128_t *)(src) + 7);                                              \
                *((__uint128_t *)(dst) + 0) = xmm0;                                              \
                *((__uint128_t *)(dst) + 1) = xmm1;                                              \
                *((__uint128_t *)(dst) + 2) = xmm2;                                              \
                *((__uint128_t *)(dst) + 3) = xmm3;                                              \
                *((__uint128_t *)(dst) + 4) = xmm4;                                              \
                *((__uint128_t *)(dst) + 5) = xmm5;                                              \
                *((__uint128_t *)(dst) + 6) = xmm6;                                              \
                *((__uint128_t *)(dst) + 7) = xmm7;                                              \
                break;                                                                           \
        }                                                                                        \
        *((uint64_t *)((uintptr_t)(dst) + (sz)-8)) = *((uint64_t *)((uintptr_t)(src) + (sz)-8)); \
    } while (0)

#define aco_memcpy(dst, src, sz)                                                 \
    do {                                                                         \
        if (aco_amd64_inline_short_aligned_memcpy_test_ok((dst), (src), (sz))) { \
            aco_amd64_inline_short_aligned_memcpy((dst), (src), (sz));           \
        } else {                                                                 \
            memcpy((dst), (src), (sz));                                          \
        }                                                                        \
    } while (0)
#endif

#ifndef aco_memcpy
#define aco_memcpy(dst, src, sz) memcpy(dst, src, sz)
#endif

static void aco_default_protector_last_word(void)
{
    aco_t *co = aco_get_co();
    // do some log about the offending `co`
    fprintf(stderr, "error: aco_default_protector_last_word triggered\n");
    fprintf(stderr,
            "error: co:%p should call `aco_exit()` instead of direct "
            "`return` in co_fp:%p to finish its execution\n",
            co, (void *)co->fp);
    aco_assert(0);
}

// aco's Global Thread Local Storage variable `co`
__thread aco_t *aco_gtls_co;
static __thread aco_cofuncp_t aco_gtls_last_word_fp = aco_default_protector_last_word;

#if defined(__i386__) || defined(_M_IX86)
static __thread void *aco_gtls_fpucw_mxcsr[2];
#elif defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
static __thread void *aco_gtls_fpucw_mxcsr[1];
#else
#error "platform no support yet"
#endif

void aco_thread_init(aco_cofuncp_t last_word_co_fp)
{
    aco_save_fpucw_mxcsr(aco_gtls_fpucw_mxcsr);

    if ((void *)last_word_co_fp != NULL) aco_gtls_last_word_fp = last_word_co_fp;
}

// This function `aco_funcp_protector` should never be
// called. If it's been called, that means the offending
// `co` didn't call aco_exit(co) instead of `return` to
// finish its execution.
void aco_funcp_protector(void)
{
    if ((void *)(aco_gtls_last_word_fp) != NULL) {
        aco_gtls_last_word_fp();
    } else {
        aco_default_protector_last_word();
    }
    aco_assert(0);
}

aco_share_stack_t *aco_share_stack_new(size_t sz)
{
    return aco_share_stack_new2(sz, 1);
}

#define aco_size_t_safe_add_assert(a, b) \
    do {                                 \
        aco_assert((a) + (b) >= (a));    \
    } while (0)

aco_share_stack_t *aco_share_stack_new2(size_t sz, char guard_page_enabled)
{
    if (sz == 0) {
        sz = 1024 * 1024 * 2;
    }
    if (sz < 4096) {
        sz = 4096;
    }
    aco_assert(sz > 0);

    size_t u_pgsz = 0;
    if (guard_page_enabled != 0) {
        // although gcc's Built-in Functions to Perform Arithmetic with
        // Overflow Checking is better, but it would require gcc >= 5.0
        long pgsz = sysconf(_SC_PAGESIZE);
        // pgsz must be > 0 && a power of two
        aco_assert(pgsz > 0 && (((pgsz - 1) & pgsz) == 0));
        u_pgsz = (size_t)((unsigned long)pgsz);
        // it should be always true in real life
        aco_assert(u_pgsz == (unsigned long)pgsz && ((u_pgsz << 1) >> 1) == u_pgsz);
        if (sz <= u_pgsz) {
            sz = u_pgsz << 1;
        } else {
            size_t new_sz;
            if ((sz & (u_pgsz - 1)) != 0) {
                new_sz = (sz & (~(u_pgsz - 1)));
                aco_assert(new_sz >= u_pgsz);
                aco_size_t_safe_add_assert(new_sz, (u_pgsz << 1));
                new_sz = new_sz + (u_pgsz << 1);
                aco_assert(sz / u_pgsz + 2 == new_sz / u_pgsz);
            } else {
                aco_size_t_safe_add_assert(sz, u_pgsz);
                new_sz = sz + u_pgsz;
                aco_assert(sz / u_pgsz + 1 == new_sz / u_pgsz);
            }
            sz = new_sz;
            aco_assert((sz / u_pgsz > 1) && ((sz & (u_pgsz - 1)) == 0));
        }
    }

    aco_share_stack_t *p = (aco_share_stack_t *)malloc(sizeof(aco_share_stack_t));
    aco_assert(p != NULL && "Aborting: failed to allocate memory");
    memset(p, 0, sizeof(aco_share_stack_t));

    if (guard_page_enabled != 0) {
        p->real_ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        aco_assert(p->real_ptr != MAP_FAILED && "Aborting: failed to allocate memory");
        p->guard_page_enabled = 1;
        aco_assert(0 == mprotect(p->real_ptr, u_pgsz, PROT_READ));

        p->ptr = (void *)(((uintptr_t)p->real_ptr) + u_pgsz);
        p->real_sz = sz;
        aco_assert(sz >= (u_pgsz << 1));
        p->sz = sz - u_pgsz;
    } else {
        // p->guard_page_enabled = 0;
        p->sz = sz;
        p->ptr = malloc(sz);
        aco_assert(p->ptr != NULL && "Aborting: failed to allocate memory");
    }

    p->owner = NULL;
#ifdef ACO_USE_VALGRIND
    p->valgrind_stk_id = VALGRIND_STACK_REGISTER(p->ptr, (void *)((uintptr_t)p->ptr + p->sz));
#endif
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
    uintptr_t u_p = (uintptr_t)(p->sz - (sizeof(void *) << 1) + (uintptr_t)p->ptr);
    u_p = (u_p >> 4) << 4;
    p->align_highptr = (void *)u_p;
#ifdef __aarch64__
    // aarch64 hardware-enforces 16 bytes stack alignment
    p->align_retptr = (void *)(u_p - 16)
#else
    p->align_retptr = (void *)(u_p - sizeof(void *));
#endif
                      * ((void **)(p->align_retptr)) = (void *)(aco_funcp_protector_asm);
    aco_assert(p->sz > (16 + (sizeof(void *) << 1) + sizeof(void *)));
    p->align_limit = p->sz - 16 - (sizeof(void *) << 1);
#else
#error "platform no support yet"
#endif
    return p;
}

void aco_share_stack_destroy(aco_share_stack_t *sstk)
{
    aco_assert(sstk != NULL && sstk->ptr != NULL);
#ifdef ACO_USE_VALGRIND
    VALGRIND_STACK_DEREGISTER(sstk->valgrind_stk_id);
#endif
    if (sstk->guard_page_enabled) {
        aco_assert(0 == munmap(sstk->real_ptr, sstk->real_sz));
        sstk->real_ptr = NULL;
        sstk->ptr = NULL;
    } else {
        free(sstk->ptr);
        sstk->ptr = NULL;
    }
    free(sstk);
}

aco_t *aco_create(aco_t *main_co, aco_share_stack_t *share_stack, size_t save_stack_sz, aco_cofuncp_t fp, void *arg)
{
    aco_t *p = (aco_t *)malloc(sizeof(aco_t));
    aco_assert(p != NULL && "Aborting: failed to allocate memory");
    memset(p, 0, sizeof(aco_t));

    if (main_co != NULL) { // non-main co
        aco_assert(share_stack != NULL);
        p->share_stack = share_stack;
#if defined(__i386__) || defined(_M_IX86)
        // POSIX.1-2008 (IEEE Std 1003.1-2008) - General Information - Data Types - Pointer Types
        // http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/functions/V2_chap02.html#tag_15_12_03
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        // push retaddr
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
#ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = aco_gtls_fpucw_mxcsr[0];
        p->reg[ACO_REG_IDX_FPU + 1] = aco_gtls_fpucw_mxcsr[1];
#endif
#elif defined(__x86_64__) || defined(_M_X64)
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
#ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = aco_gtls_fpucw_mxcsr[0];
#endif
#elif defined(__aarch64__)
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
#ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = aco_gtls_fpucw_mxcsr[0];
#endif
#else
#error "platform no support yet"
#endif
        p->main_co = main_co;
        p->arg = arg;
        p->fp = fp;
        if (save_stack_sz == 0) {
            save_stack_sz = 64;
        }
        p->save_stack.ptr = malloc(save_stack_sz);
        aco_assert(p->save_stack.ptr != NULL && "Aborting: failed to allocate memory");
        p->save_stack.sz = save_stack_sz;
#if defined(__i386__) || defined(_M_IX86) || defined(__x86_64__) || defined(_M_X64) || defined(__aarch64__)
        p->save_stack.valid_sz = 0;
#else
#error "platform no support yet"
#endif
        return p;
    } else { // main co
        p->main_co = NULL;
        p->arg = arg;
        p->fp = fp;
        p->share_stack = NULL;
        p->save_stack.ptr = NULL;
        return p;
    }
    aco_assert(0);
}

aco_attr_no_asan static void aco_own_stack(aco_t *co)
{
    if (co->share_stack->owner != NULL) {
        aco_t *owner_co = co->share_stack->owner;
        aco_assert(owner_co->share_stack == co->share_stack);
        aco_assert(
            ((uintptr_t)(owner_co->share_stack->align_retptr) >= (uintptr_t)(owner_co->reg[ACO_REG_IDX_SP]))
            && ((uintptr_t)(owner_co->share_stack->align_highptr) - (uintptr_t)(owner_co->share_stack->align_limit)
                <= (uintptr_t)(owner_co->reg[ACO_REG_IDX_SP])));
        owner_co->save_stack.valid_sz =
            (uintptr_t)(owner_co->share_stack->align_retptr) - (uintptr_t)(owner_co->reg[ACO_REG_IDX_SP]);
        if (owner_co->save_stack.sz < owner_co->save_stack.valid_sz) {
            free(owner_co->save_stack.ptr);
            owner_co->save_stack.ptr = NULL;
            while (1) {
                owner_co->save_stack.sz = owner_co->save_stack.sz << 1;
                aco_assert(owner_co->save_stack.sz > 0);
                if (owner_co->save_stack.sz >= owner_co->save_stack.valid_sz) {
                    break;
                }
            }
            owner_co->save_stack.ptr = malloc(owner_co->save_stack.sz);
            aco_assert(owner_co->save_stack.ptr != NULL && "Aborting: failed to allocate memory");
        }
        // TODO: optimize the performance penalty of memcpy function call
        //   for very short memory span
        if (owner_co->save_stack.valid_sz > 0) {
            aco_memcpy(owner_co->save_stack.ptr, owner_co->reg[ACO_REG_IDX_SP], owner_co->save_stack.valid_sz);
            owner_co->save_stack.ct_save++;
        }
        if (owner_co->save_stack.valid_sz > owner_co->save_stack.max_cpsz) {
            owner_co->save_stack.max_cpsz = owner_co->save_stack.valid_sz;
        }
        owner_co->share_stack->owner = NULL;
        owner_co->share_stack->align_validsz = 0;
    }
    aco_assert(co->share_stack->owner == NULL);

    aco_assert(co->save_stack.valid_sz <= co->share_stack->align_limit - sizeof(void *));
    // TODO: optimize the performance penalty of memcpy function call
    //   for very short memory span
    if (co->save_stack.valid_sz > 0) {
        aco_memcpy((void *)((uintptr_t)(co->share_stack->align_retptr) - co->save_stack.valid_sz), co->save_stack.ptr,
                   co->save_stack.valid_sz);
        co->save_stack.ct_restore++;
    }
    if (co->save_stack.valid_sz > co->save_stack.max_cpsz) {
        co->save_stack.max_cpsz = co->save_stack.valid_sz;
    }
    co->share_stack->align_validsz = co->save_stack.valid_sz + sizeof(void *);
    co->share_stack->owner = co;
}

aco_attr_no_asan void aco_resume(aco_t *resume_co)
{
    aco_assert(resume_co != NULL && resume_co->main_co != NULL && !aco_is_end(resume_co));
    if (resume_co->share_stack->owner != resume_co) {
        aco_own_stack(resume_co);
    }
    aco_gtls_co = resume_co;
    acosw(resume_co->main_co, resume_co);
    aco_gtls_co = resume_co->main_co;
}

aco_attr_no_asan void aco_yield_to(aco_t *resume_co)
{
    if (aco_unlikely(resume_co == NULL || resume_co->main_co == NULL || aco_is_end(resume_co))) {
        // An error message here is helpful because
        // we are running in a non-main co
        fprintf(stderr, "Aborting: %s(resume_co=%p): resume_co is not valid: %s:%d\n", __PRETTY_FUNCTION__, resume_co,
                __FILE__, __LINE__);
        abort();
    }
    aco_t *yield_co = aco_gtls_co;
    if (aco_unlikely(resume_co == yield_co)) {
        // Nothing to do
        return;
    }
    if (aco_unlikely(resume_co->main_co != yield_co->main_co
                     // A co cannot save its own stack
                     || resume_co->share_stack == yield_co->share_stack)) {
        fprintf(stderr,
                "Aborting: %s(resume_co=%p): resume_co has a different main co or share the same stack: %s:%d\n",
                __PRETTY_FUNCTION__, resume_co, __FILE__, __LINE__);
        abort();
    }
    // The test below is unlikely because
    // aco_yield_to() is often called between two non-main cos
    if (aco_unlikely(resume_co->share_stack->owner != resume_co)) {
        aco_own_stack(resume_co);
    }
    aco_gtls_co = resume_co;
    acosw(yield_co, resume_co);
}

void aco_destroy(aco_t *co)
{
    aco_assert(co != NULL);
    if (aco_is_main_co(co)) {
        free(co);
    } else {
        if (co->share_stack->owner == co) {
            co->share_stack->owner = NULL;
            co->share_stack->align_validsz = 0;
        }
        free(co->save_stack.ptr);
        co->save_stack.ptr = NULL;
        free(co);
    }
}

void *aco_getspecific(pthread_key_t key)
{
    aco_t *co = aco_get_co();
    if (!co || !co->main_co) {
        return pthread_getspecific(key);
    } else {
        if (co->specifics == NULL || co->specifics->values == NULL || co->specifics->size <= key) {
            return NULL;
        }
        return co->specifics->values[key];
    }
}

int aco_setspecific(pthread_key_t key, const void *value)
{
    aco_t *co = aco_get_co();
    if (!co || !co->main_co) {
        return pthread_setspecific(key, value);
    } else {
        if (co->specifics == NULL) {
            co->specifics = (struct speclist *)calloc(sizeof(struct speclist), 1);
            if (co->specifics == NULL) {
                return -ENOMEM;
            }
        }
        if (co->specifics) {
            if (key >= co->specifics->size) {
                size_t num = 2 * co->specifics->size;
                if (key >= num) {
                    num = key + 4;
                }
                void *values = realloc(co->specifics->values, sizeof(void *) * num);
                if (values == NULL) {
                    return -ENOMEM;
                }
                co->specifics->values = (void **)values;
            }
            co->specifics->values[key] = (void *)value;
        }
    }

    return 0;
}
