// Copyright 2018 Sen Han <00hnes@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "aco.h"
#include <stdio.h>
#include "aco_specific.h"

struct __data {
    int id;
    const char *name;
};
ACO_SPECIFIC_DEFINE(__data, __test);

static void foo(int ct)
{
    aco_log_always("co: %p: yield to main_co: %d\n", aco_self(), *((int *)(aco_get_arg())));
    aco_yield();
    *((int *)(aco_get_arg())) = ct + 1;
}

static void co_fp0()
{
    aco_log_always("co: %p: entry: %d\n", aco_self(), *((int *)(aco_get_arg())));
    int ct = 0;
    while (ct < 6) {
        foo(ct);
        ct++;
    }
    aco_log_always("co: %p:  exit to main_co: %d\n", aco_self(), *((int *)(aco_get_arg())));
    aco_exit();
}

int main()
{
    aco_thread_init(NULL);

    aco_t *main_co = aco_create(NULL, NULL, 0, NULL, NULL);
    aco_share_stack_t *sstk = aco_share_stack_new(0, true);

    int co_ct_arg_point_to_me = 0;
    aco_t *co = aco_create(main_co, sstk, 0, co_fp0, &co_ct_arg_point_to_me);

    int ct = 0;
    while (ct < 6) {
        aco_assert(!aco_is_end(co));
        aco_log_always("main_co: yield to co: %p: %d\n", co, ct);
        aco_resume(co);
        aco_assert(co_ct_arg_point_to_me == ct);
        ct++;
    }
    aco_log_always("main_co: yield to co: %p: %d\n", co, ct);
    aco_resume(co);
    aco_assert(co_ct_arg_point_to_me == ct);
    aco_assert(aco_is_end(co));

    aco_log_always("main_co: destroy and exit\n");
    aco_destroy(co);
    co = NULL;
    aco_share_stack_destroy(sstk);
    sstk = NULL;
    aco_destroy(main_co);
    main_co = NULL;

    __test->id = 10;
    __test->name = "test";

    return 0;
}
