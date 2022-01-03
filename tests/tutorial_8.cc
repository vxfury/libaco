#include "aco.h"
#include "aco_specific.h"

#define _GNU_SOURCE
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/syscall.h>

size_t curr_co_amount;
size_t curr_co_index;
aco_t **coarray;

void yield_to_next_co()
{
    aco_assert(curr_co_amount > 0);
    curr_co_index = (curr_co_index + 1) % curr_co_amount;
    aco_yield_to(coarray[curr_co_index]);
}

struct dataA {
    int a;
    int b;
};
ACO_SPECIFIC(dataA, __a)

struct dataB {
    const char *a;
    const char *b;
};
ACO_SPECIFIC(dataB, __b);

void co_fp0()
{
    int ct = 0;
    int loop_ct = (int)((uintptr_t)(aco_self()->arg));
    if (loop_ct < 0) {
        loop_ct = 0;
    }

    while (ct < loop_ct) {
        printf("a = %d, b = %d", ++__a->a, ++__a->b);
        yield_to_next_co();
        ct++;
    }
    printf("a = %d, b = %d", __a->a, __a->b);
    aco_exit();
}

int main(void)
{
    aco_thread_init(NULL);

    time_t seed_t = time(NULL);
    aco_assert((time_t)-1 != seed_t);
    srand(seed_t);

    size_t co_amount = 100;
    curr_co_amount = co_amount;


    // create co
    aco_assert(co_amount > 0);
    aco_t *main_co = aco_create(NULL, NULL, 0, NULL, NULL);
    // NOTE: size_t_safe_mul
    coarray = (aco_t **)malloc(sizeof(void *) * co_amount);
    aco_assert(coarray != NULL);
    memset(coarray, 0, sizeof(void *) * co_amount);
    size_t ct = 0;
    while (ct < co_amount) {
        aco_share_stack_t *private_sstk = aco_share_stack_new(0, ct % 4);
        coarray[ct] = aco_create(main_co, private_sstk, 0, co_fp0, (void *)((uintptr_t)rand() % 1000));
        private_sstk = NULL;
        ct++;
    }

    // naive scheduler
    printf("scheduler start: co_amount:%zu\n", co_amount);
    aco_t *curr_co = coarray[curr_co_index];
    while (curr_co_amount > 0) {
        aco_resume(curr_co);
        // Update curr_co because aco_yield_to() may have changed it
        curr_co = coarray[curr_co_index];
        aco_assert(aco_is_end(curr_co));
        printf("aco_destroy: co currently at:%zu\n", curr_co_index);
        aco_share_stack_t *private_sstk = curr_co->share_stack;
        aco_destroy(curr_co);
        aco_share_stack_destroy(private_sstk);
        private_sstk = NULL;
        curr_co_amount--;
        if (curr_co_index < curr_co_amount) {
            coarray[curr_co_index] = coarray[curr_co_amount];
        } else {
            curr_co_index = 0;
        }
        coarray[curr_co_amount] = NULL;
        curr_co = coarray[curr_co_index];
    }

    // co cleaning
    ct = 0;
    while (ct < co_amount) {
        aco_assert(coarray[ct] == NULL);
        ct++;
    }
    aco_destroy(main_co);
    main_co = NULL;
    free(coarray);

    printf("sheduler exit\n");

    return 0;
}
