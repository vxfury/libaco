#ifndef ACO_SPECIFIC_H
#define ACO_SPECIFIC_H

#include "aco.h"
#include <pthread.h>

#define ACO_SPECIFIC(type, name)                                    \
    static pthread_key_t __aco_key_##type;                                 \
    static bool __aco_once_initialized_##type = false;                     \
    static pthread_once_t __aco_once_##type = PTHREAD_ONCE_INIT;           \
    static void __aco_create_key_##type()                                  \
    {                                                                      \
        (void)pthread_key_create(&__aco_key_##type, NULL);                 \
    }                                                                      \
    template <class T>                                                     \
    class coroutine_data_##type {                                          \
      public:                                                              \
        inline T *operator->()                                             \
        {                                                                  \
            if (!__aco_once_initialized_##type) {                          \
                pthread_once(&__aco_once_##type, __aco_create_key_##type); \
                __aco_once_initialized_##type = true;                      \
            }                                                              \
            T *p = (T *)aco_getspecific(__aco_key_##type);                 \
            if (!p) {                                                      \
                p = (T *)calloc(1, sizeof(T));                             \
                int ret = aco_setspecific(__aco_key_##type, p);            \
                if (ret) {                                                 \
                    if (p) {                                               \
                        free(p);                                           \
                        p = NULL;                                          \
                    }                                                      \
                }                                                          \
            }                                                              \
            return p;                                                      \
        }                                                                  \
    };                                                                     \
                                                                           \
    static coroutine_data_##type<type> name;


#if 0
template <typename T>
class aco_specific {
  public:
    aco_specific &instance()
    {
        static aco_specific __;
        return __;
    }

    inline T *operator->()
    {
        T *p = (T *)aco_getspecific(__aco_key);
        if (p == NULL) {
            p = new T;
            if (p && aco_setspecific(__aco_key, p) != 0) {
                free(p);
                p = NULL;
            }
        }

        return p;
    }

  private:
    T v;
    pthread_key_t __aco_key;
    pthread_once_t __aco_once = PTHREAD_ONCE_INIT;

    aco_specific()
    {
        pthread_once(&__aco_once, [&]() -> void {
            pthread_key_create(&__aco_key, NULL);
        });
    }
    ~aco_specific() {}
};
#endif

/*
invoke only once in the whole program
CoRoutineSetSpecificCallBack(CoRoutineGetSpecificFunc_t pfnGet,CoRoutineSetSpecificFunc_t pfnSet)

struct MyData_t
{
    int iValue;
    char szValue[100];
};
ACO_SPECIFIC( MyData_t,__routine );

int main()
{
    CoRoutineSetSpecificCallBack( aco_getspecific,aco_setspecific );

    __routine->iValue = 10;
    strcpy( __routine->szValue,"hello world" );

    return 0;
}
*/

#endif
