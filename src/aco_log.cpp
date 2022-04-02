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

#include <math.h>
#include <time.h>
#include <unistd.h>
#include <sys/time.h>

#include <fstream>
#include <iomanip>
#include <sstream>
#include <iostream>

#include <sys/shm.h>
#include <sys/shm.h>
#include <sys/stat.h>

#include "aco_log.h"

#define TRACE(...) printf("%s:%d ", __FILE__, __LINE__), printf(__VA_ARGS__), printf("\n")

namespace aco
{
namespace logging
{
struct logging_cache {
    void *details;                 // head + content
    unsigned int details_size;     // details size
    unsigned int details_capacity; // details capacity

    logging_cache(void *addr, size_t size) : details(addr), details_size(0), details_capacity(size) {}

    enum {
        LOG_HEAD_NONE = 0,
        LOG_HEAD_FULL = 1,
        LOG_HEAD_DEFAULT = 2,

        LOG_OFFSET_DISCARD = 0x10,
    };

    int add(unsigned int options, int level, const char *location, const char *fmt, ...)
    {
        unsigned int remain = details_capacity - details_size;
        char *p = (char *)((uintptr_t)details + details_size), *q = p;

        unsigned int headlen = sizeof("hh::mm::ss.nnn <> []")
                               + static_cast<unsigned>(ceil(log10((double)level))) + strlen(location);
        if (remain <= headlen) {
            TRACE("Out of memory: remain %u, headlen %u", remain, headlen);
            return -ENOMEM;
        }

        /* head */
        {
            struct tm tm;
            struct timeval tv;
            gettimeofday(&tv, NULL);
            localtime_r(&tv.tv_sec, &tm);
            int len = strftime(p, remain, "%H:%M:%S", &tm);
            p += len, remain -= len;
            len =
                snprintf(p, remain, ".%03u <%d> [%s] ", (unsigned int)(tv.tv_usec / 1000), level, location);
            p += len, remain -= len;
        }

        /* content */
        unsigned int datalen = 0;
        {
            va_list ap;
            va_start(ap, fmt);
            datalen = vsnprintf(p, remain, fmt, ap);
            p += datalen, remain -= datalen;
            va_end(ap);
        }

        TRACE("End: %s", q);

        return 0;
    }

    template <typename Logger>
    class cleaner {
      public:
        cleaner(Logger &logger) : drop(false), offset(logger.details_size), logger(logger) {}

        ~cleaner()
        {
            if (drop) {
                logger.details_size = offset;
            }
        }

        size_t size() const
        {
            return logger.details_size - offset;
        }

        void discard(bool drop_or_not = true)
        {
            drop = drop_or_not;
        }

      private:
        bool drop;
        Logger &logger;
        unsigned int offset;
    };

    std::shared_ptr<cleaner<logging_cache>> make_cleaner()
    {
        return std::make_shared<cleaner<logging_cache>>(*this);
    }
};

namespace shared_memory
{
int foo()
{
    int segment_id;
    char *shared_memory;
    int segment_size;
    const int shared_segment_size = 0x6400;

    /* Allocate a shared memory segment.  */
    segment_id = shmget(IPC_PRIVATE, shared_segment_size,
                        IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    /* Attach the shared memory segment.  */
    printf("Shared memory segment ID is %d\n", segment_id);
    shared_memory = (char *)shmat(segment_id, 0, 0);
    printf("shared memory attached at address %p\n", shared_memory);

    /* Determine the segment's size. */
    {
        struct shmid_ds shmbuffer;
        shmctl(segment_id, IPC_STAT, &shmbuffer);
        segment_size = shmbuffer.shm_segsz;
        printf("segment size: %d\n", segment_size);
    }

    /* Write a string to the shared memory segment.  */
    sprintf(shared_memory, "Hello, world.");

    /* Detach the shared memory segment.  */
    shmdt(shared_memory);

    return 0;
}
} // namespace shared_memory

constexpr size_t LINE_SIZE = 4096;
constexpr size_t STAGE_SIZE = 256;

detail::detail(int id, const char *location, int level, const char *fmt, va_list ap)
    : id(id), level(level), location(location)
{
    gettimeofday(&tv, NULL);
    {
        char buff[LINE_SIZE];
        vsnprintf(buff, sizeof(buff), fmt, ap);
        content += std::string(buff);
    }
}

std::string detail::time() const
{
    char buffer[20];
    struct tm lctime;
    localtime_r(&tv.tv_sec, &lctime);
    snprintf(buffer, sizeof(buffer), "%02d/%02d %02d:%02d:%02d.%03d", lctime.tm_mon + 1, lctime.tm_mday,
             lctime.tm_hour, lctime.tm_min, lctime.tm_sec, (int)(((tv.tv_usec + 500) / 1000) % 1000));
    return std::string(buffer);
}

static std::string generate_uuid(const char *fmt, va_list ap)
{
    char buff[128], *p = buff;
    size_t remain = sizeof(buff);

    int len = vsnprintf(p, remain, fmt, ap);
    if (len >= 0 && len < remain) {
        p += len, remain -= len;
        if (remain > sizeof("YYYY-MM-DD hh::mm:ss.nnn")) {
            *p++ = '(', *p = '\0', remain--;
            struct tm tm;
            struct timeval tv;
            gettimeofday(&tv, NULL);
            localtime_r(&tv.tv_sec, &tm);
            len = strftime(p, remain, "%Y-%m-%d %H:%M:%S", &tm);
            p += len, remain -= len;
            *p++ = '.', *p = '\0', remain--;
            len = snprintf(p, remain, "%03u)", (unsigned int)(tv.tv_usec / 1000));
            p += len, remain -= len;
        }
    }

    return std::string(buff);
}

static void printer_default(int id, const std::string &uuid, const std::vector<detail> &details,
                            const std::vector<std::string> &stages);

cached_logger::cached_logger() : id(0)
{
    char buff[32];
    struct tm tm;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    localtime_r(&tv.tv_sec, &tm);
    if (strftime(buff, sizeof(buff), "%Y-%m-%d %H:%M:%S", &tm) != 0) {
        uuid = "(" + std::string(buff) + "." + std::to_string(((tv.tv_usec + 500) / 1000) % 1000) + ")";
    }
}

cached_logger::cached_logger(const char *fmt, ...) : id(0)
{
    va_list ap;
    va_start(ap, fmt);
    uuid = generate_uuid(fmt, ap);
    va_end(ap);
}

cached_logger::~cached_logger()
{
    flush();
}

void cached_logger::clear()
{
    id = 0;
    uuid.clear();
    stages.clear();
    details.clear();
}

void cached_logger::flush()
{
    if (printers.size() == 0) {
        printer_default(id, uuid, details, stages);
    } else {
        for (auto &printer : printers) {
            printer(id, uuid, details, stages);
        }
    }
}

void cached_logger::reset(const char *fmt, ...)
{
    flush();
    clear();

    if (fmt != nullptr) {
        va_list ap;
        va_start(ap, fmt);
        uuid = generate_uuid(fmt, ap);
        va_end(ap);
    }
}

void cached_logger::add_detail(const char *location, int level, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    details.emplace_back(id++, location, level, fmt, ap);
    va_end(ap);
}

void cached_logger::add_stage(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    char buff[STAGE_SIZE];
    vsnprintf(buff, sizeof(buff), fmt, ap);
    stages.emplace_back(buff);
    va_end(ap);
}

void cached_logger::add_printer(printer_type printer)
{
    printers.push_back(printer);
}

static void printer_default(int id, const std::string &uuid, const std::vector<detail> &details,
                            const std::vector<std::string> &stages)
{
    enum { NONE, TIME, INFO, WARN, ERROR };
    bool csi_supported = isatty(STDOUT_FILENO);
    auto format_content = [=](std::string content, int type) -> std::string {
        if (csi_supported) {
            switch (type) {
                case TIME:
                    return "\033[2;3m" + content + "\033[0m";
                case INFO:
                    return "\033[38;2;85;255;255m" + content + "\033[0m";
                case WARN:
                    return "\033[38;2;255;199;6;1m" + content + "\033[0m";
                case ERROR:
                    return "\033[38;2;255;0;0;1m" + content + "\033[0m";
                default:
                    return content;
            }
        }
        return content;
    };

    if (stages.size() > 0 || details.size() > 0) {
        if (stages.size() > 0) {
            std::string tmp;
            for (size_t i = 0; i < stages.size(); i++) {
                tmp += stages[i];
                if (i != stages.size() - 1) {
                    tmp += " -> ";
                }
            }
            printf("%s: %s\n", uuid.c_str(), tmp.c_str());
        }
        if (details.size() > 0) {
            auto width = static_cast<unsigned>(ceil(log10((double)id)));
            auto percent = static_cast<float>(100.0 * details.size() / id);
            std::string prefix = uuid.substr(0, uuid.length() - sizeof("YYYY-MM-DD hh::mm:ss.nnn"));
            printf("%s: %.2f%% logs keeped.\n", prefix.c_str(), percent);
            for (auto const &item : details) {
                printf("%s  >%.*d [%d] %s [%s]: %s\n", prefix.c_str(), width, item.id, item.level,
                       format_content(item.time(), TIME).c_str(), item.location,
                       format_content(item.content, item.level <= 1 ? ERROR : NONE).c_str());
            }
        }
    }
}
} // namespace logging
} // namespace aco


int main(int argc, char **argv)
{
    char *buffer = (char *)malloc(1024 * 1024);
    aco::logging::logging_cache cache(buffer, 1024 * 1024);

    for (auto i = 0; i < 5; i++) {
        cache.add(0, 1, LOCATION(__FILE__, __LINE__), "test %s %d\n", "word", 100);
        auto cleaner = cache.make_cleaner();
        for (int j = 0; j < 5; j++) {
            cache.add(0, 1, LOCATION(__FILE__, __LINE__), "test %s %d\n", "word", 100);
        }
        cleaner->discard();
    }
}
