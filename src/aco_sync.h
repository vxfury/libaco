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

#ifndef ACO_INNER_H
#define ACO_INNER_H

#include <chrono>

#include "aco.h"
#include "aco_timer.h"

class aco_mutex;

class aco_cond {
  public:
    enum class cv_status { no_timeout, timeout };

    void notify_one();
    void notify_all();

    void wait(aco_mutex &lck);

    template <class Predicate>
    void wait(aco_mutex &lck, Predicate pred);

    template <class Rep, class Period>
    cv_status wait_for(aco_mutex &lck, const std::chrono::duration<Rep, Period> &rel_time);

    template <class Rep, class Period, class Predicate>
    bool wait_for(aco_mutex &lck, const std::chrono::duration<Rep, Period> &rel_time, Predicate pred);

    template <class Clock, class Duration>
    cv_status wait_until(aco_mutex &lck, const std::chrono::time_point<Clock, Duration> &abs_time);

    template <class Clock, class Duration, class Predicate>
    bool wait_until(aco_mutex &lck, const std::chrono::time_point<Clock, Duration> &abs_time,
                    Predicate pred);

  private:
    async::timer_event_list slot;
};

class aco_mutex {
  public:
    aco_mutex()
    {
        m_iWaitItemCnt = 0;
    }

    ~aco_mutex() {}

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
    aco_cond cond;
    int m_iWaitItemCnt;
};


class aco_lock_guard {
  public:
    aco_lock_guard(aco_mutex &lck) : m_mutex(lck)
    {
        m_mutex.lock();
    }

    ~aco_lock_guard()
    {
        m_mutex.unlock();
    }

  private:
    aco_mutex &m_mutex;
};

#endif
