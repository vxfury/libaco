/**
 * Copyright 2022 Kiran Nowak(kiran.nowak@gmail.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <sys/syscall.h>

#include "aco.h"

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

#ifndef aco_memcpy
    #include "aco_memcpy_optimized.c"
    #ifdef aco_memcpy_optimized
        #define aco_memcpy(dst, src, sz) aco_memcpy_optimized(dst, src, sz)
    #else
        #define aco_memcpy(dst, src, sz) memcpy(dst, src, sz)
    #endif
#endif

void aco_save_fpucw_mxcsr(void *p) __asm__("aco_save_fpucw_mxcsr");
void aco_runtime_protector_asm(void) __asm__("aco_runtime_protector_asm");

static void aco_default_protector_last_word(void)
{
    aco_t *co = aco_self();
    // do some log about the offending `co`
    fprintf(stderr, "error: aco_default_protector_last_word triggered\n");
    fprintf(stderr,
            "error: co:%p should call `aco_exit()` instead of direct "
            "`return` in co_fp:%p to finish its execution\n",
            co, (void *)co->fp);
    aco_assert(0);
}

// aco's Global Thread Local Storage variable `co`
static __thread aco_t *gtls_co;
static __thread void *gtls_fpucw_mxcsr[8 / sizeof(void *)];
static __thread void (*gtls_protector_last_word)(void) = aco_default_protector_last_word;

void aco_thread_init(void (*last_word_co_fp)(void))
{
#if 0
// clang-format off
#if defined(__i386__) || defined(_M_IX86)
    __asm__ __volatile__
    (
        "mov     eax, DWORD PTR [esp+0x4]\n"
        "fnstcw  WORD PTR  [eax]\n"
        "stmxcsr DWORD PTR [eax+0x4]\n"
    );
#elif defined(__x86_64__) || defined(_M_X64)
    __asm__ __volatile__
    (
        "fnstcw  %0\n"
        "stmxcsr %0[+4]\n"
        : "+m" (gtls_fpucw_mxcsr[0])
        :
        :
    );
#endif
    // clang-format on
#endif
    aco_save_fpucw_mxcsr(gtls_fpucw_mxcsr);

    if ((void *)last_word_co_fp != NULL) gtls_protector_last_word = last_word_co_fp;
}

// This function `aco_funcp_protector` should never be
// called. If it's been called, that means the offending
// `co` didn't call aco_exit(co) instead of `return` to
// finish its execution.
void aco_funcp_protector(void)
{
    if ((void *)(gtls_protector_last_word) != NULL) {
        gtls_protector_last_word();
    } else {
        aco_default_protector_last_word();
    }
    aco_assert(0);
}

#define aco_safe_uadd_assert(a, b)    \
    do {                              \
        aco_assert((a) + (b) >= (a)); \
    } while (0)

aco_share_stack_t *aco_share_stack_new(size_t sz, bool enable_guard_page)
{
    if (sz == 0) {
        sz = 1024 * 1024 * 2;
    }
    if (sz < 4096) {
        sz = 4096;
    }
    aco_assert(sz > 0);

    aco_share_stack_t *p = (aco_share_stack_t *)malloc(sizeof(aco_share_stack_t));
    aco_assert(p != NULL && "Aborting: failed to allocate memory");
    memset(p, 0, sizeof(aco_share_stack_t));

    if (enable_guard_page) {
        size_t u_pgsz = 0;

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
                aco_safe_uadd_assert(new_sz, (u_pgsz << 1));
                new_sz = new_sz + (u_pgsz << 1);
                aco_assert(sz / u_pgsz + 2 == new_sz / u_pgsz);
            } else {
                aco_safe_uadd_assert(sz, u_pgsz);
                new_sz = sz + u_pgsz;
                aco_assert(sz / u_pgsz + 1 == new_sz / u_pgsz);
            }
            sz = new_sz;
            aco_assert((sz / u_pgsz > 1) && ((sz & (u_pgsz - 1)) == 0));
        }

        p->guard_page_ptr = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        aco_assert(p->guard_page_ptr != MAP_FAILED && "Aborting: failed to allocate memory");
        aco_assert(0 == mprotect(p->guard_page_ptr, u_pgsz, PROT_READ));

        p->ptr = (void *)(((uintptr_t)p->guard_page_ptr) + u_pgsz);
        p->guard_page_size = sz;
        aco_assert(sz >= (u_pgsz << 1));
        p->sz = sz - u_pgsz;
    } else {
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
    p->align_retptr = (void *)(u_p - 16);
    #else
    p->align_retptr = (void *)(u_p - sizeof(void *));
    #endif
    *((void **)(p->align_retptr)) = (void *)(aco_runtime_protector_asm);
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
    if (sstk->guard_page_ptr != NULL) {
        // guard page enabled
        aco_assert(0 == munmap(sstk->guard_page_ptr, sstk->guard_page_size));
        sstk->guard_page_ptr = NULL;
        sstk->ptr = NULL;
    } else {
        free(sstk->ptr);
        sstk->ptr = NULL;
    }
    free(sstk);
}

aco_t *aco_create(aco_t *main_co, aco_share_stack_t *share_stack, size_t save_stack_sz, void (*fp)(void),
                  void *arg)
{
    aco_t *p = (aco_t *)malloc(sizeof(aco_t));
    aco_assert(p != NULL && "Aborting: failed to allocate memory");
    memset(p, 0, sizeof(aco_t));

    if (main_co != NULL) { // non-main co
        aco_assert(share_stack != NULL);
        p->share_stack = share_stack;
#if defined(__i386__) || defined(_M_IX86)
        // POSIX.1-2008 (IEEE Std 1003.1-2008) - General Information - Data
        // Types - Pointer Types
        // http://pubs.opengroup.org/onlinepubs/9699919799.2008edition/functions/V2_chap02.html#tag_15_12_03
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        // push retaddr
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
    #ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = gtls_fpucw_mxcsr[0];
        p->reg[ACO_REG_IDX_FPU + 1] = gtls_fpucw_mxcsr[1];
    #endif
#elif defined(__x86_64__) || defined(_M_X64)
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
    #ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = gtls_fpucw_mxcsr[0];
    #endif
#elif defined(__aarch64__)
        p->reg[ACO_REG_IDX_RETADDR] = (void *)fp;
        p->reg[ACO_REG_IDX_SP] = p->share_stack->align_retptr;
    #ifndef ACO_CONFIG_SHARE_FPU_MXCSR_ENV
        p->reg[ACO_REG_IDX_FPU] = gtls_fpucw_mxcsr[0];
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
            && ((uintptr_t)(owner_co->share_stack->align_highptr)
                    - (uintptr_t)(owner_co->share_stack->align_limit)
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
            aco_memcpy(owner_co->save_stack.ptr, owner_co->reg[ACO_REG_IDX_SP],
                       owner_co->save_stack.valid_sz);
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
        aco_memcpy((void *)((uintptr_t)(co->share_stack->align_retptr) - co->save_stack.valid_sz),
                   co->save_stack.ptr, co->save_stack.valid_sz);
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
    gtls_co = resume_co;
    acosw(resume_co->main_co, resume_co);
    gtls_co = resume_co->main_co;
}

aco_attr_no_asan void aco_yield_to(aco_t *resume_co)
{
    if (aco_unlikely(resume_co == NULL || resume_co->main_co == NULL || aco_is_end(resume_co))) {
        // An error message here is helpful because
        // we are running in a non-main co
        fprintf(stderr, "Aborting: %s(resume_co=%p): resume_co is not valid: %s:%d\n", __PRETTY_FUNCTION__,
                resume_co, __FILE__, __LINE__);
        abort();
    }
    aco_t *yield_co = gtls_co;
    if (aco_unlikely(resume_co == yield_co)) {
        // Nothing to do
        return;
    }
    if (aco_unlikely(resume_co->main_co != yield_co->main_co
                     // A co cannot save its own stack
                     || resume_co->share_stack == yield_co->share_stack)) {
        fprintf(stderr,
                "Aborting: %s(resume_co=%p): resume_co has a different main co "
                "or share the same stack: %s:%d\n",
                __PRETTY_FUNCTION__, resume_co, __FILE__, __LINE__);
        abort();
    }
    // The test below is unlikely because
    // aco_yield_to() is often called between two non-main cos
    if (aco_unlikely(resume_co->share_stack->owner != resume_co)) {
        aco_own_stack(resume_co);
    }
    gtls_co = resume_co;
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
    aco_t *co = aco_self();
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
    aco_t *co = aco_self();
    if (!co || !co->main_co) {
        return pthread_setspecific(key, value);
    } else {
        if (co->specifics == NULL) {
            co->specifics = (struct speclist *)calloc(sizeof(struct speclist), 1);
            if (co->specifics == NULL) {
                return -ENOMEM;
            }
        }
        if (key >= co->specifics->size) {
            size_t num = 2 * co->specifics->size;
            if (key >= num) {
                num = key + 4;
            }
            void *values = realloc(co->specifics->values, sizeof(void *) * num);
            if (values == NULL) {
                return -ENOMEM;
            }
            co->specifics->size = num;
            co->specifics->values = (void **)values;
        }
#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-qual"
#endif
        co->specifics->values[key] = (void *)value;
#ifdef __GNUC__
    #pragma GCC diagnostic pop
#elif defined(__clang__)
    #pragma clang diagnostic pop
#endif
    }

    return 0;
}

aco_t *aco_self(void)
{
    return gtls_co;
}

pid_t aco_getpid(void)
{
    static __thread pid_t pid = 0;
    if (pid == 0) {
        pid = getpid();
    }
    return pid;
}

pid_t aco_gettid(void)
{
    static __thread pid_t tid = 0;
    if (tid == 0) {
#if defined(__APPLE__) && defined(__MACH__)
        uint64_t tid64;
        pthread_threadid_np(NULL, &tid64);
        tid = (pid_t)tid64;
        if (-1 == (long)tid) {
            tid = aco_getpid();
        }
#elif defined(__FreeBSD__)
        syscall(SYS_thr_self, &tid);
        if (tid < 0) {
            tid = aco_getpid();
        }
#else
        tid = syscall(__NR_gettid);
#endif
    }

    return tid;
}

pid_t aco_getrid(void)
{
    aco_t *co = aco_self();
    if (co) {
        return (pid_t)(((uintptr_t)&gtls_co - (uintptr_t)co) & 0x7FFFFFFF);
    } else {
        return 0;
    }
}
