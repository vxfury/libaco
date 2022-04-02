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

#ifndef ACO_SPECIFIC_H
#define ACO_SPECIFIC_H

#include "aco.h"
#include <pthread.h>

void *aco_getspecific(pthread_key_t key);
int aco_setspecific(pthread_key_t key, const void *value);

template <typename T>
class aco_specific {
  public:
    static aco_specific &instance()
    {
        static aco_specific __;
        pthread_once(&__.__aco_once, []() -> void {
            pthread_key_create(&__.__aco_key, [](void *value) {
                if (value != NULL) {
                    T *p = (T *)value;
                    delete p;
                }
            });
        });
        return __;
    }

    inline T *operator->()
    {
        T *p = (T *)aco_getspecific(__aco_key);
        if (p == NULL) {
            p = new T;
            if (p && aco_setspecific(__aco_key, p) != 0) {
                delete p;
                p = NULL;
            }
        }

        return p;
    }

  private:
    pthread_key_t __aco_key;
    pthread_once_t __aco_once = PTHREAD_ONCE_INIT;

    aco_specific() {}
    ~aco_specific() {}
};
#define ACO_SPECIFIC_DEFINE(type, name) static aco_specific<type> &name = aco_specific<type>::instance();

#endif
