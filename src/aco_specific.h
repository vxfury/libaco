#ifndef ACO_SPECIFIC_H
#define ACO_SPECIFIC_H

#include "aco.h"
#include <pthread.h>

template <typename T>
class aco_specific {
  public:
    static aco_specific &instance()
    {
        static aco_specific __;
        return __;
    }

    inline T *operator->()
    {
        T *p = (T *)aco_getspecific(instance().__aco_key);
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

    static void create_key(void)
    {
        pthread_once(&instance().__aco_once, []() -> void {
            pthread_key_create(&instance().__aco_key, NULL);
        });
    }

    aco_specific()
    {
        pthread_once(&__aco_once, aco_specific<T>::create_key);
    }
    ~aco_specific() {}
};
#define ACO_SPECIFIC(type, name) aco_specific<type> &name = aco_specific<type>::instance();

#endif
