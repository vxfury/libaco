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

#include <map>

#include "aco.h"
#include "aco_sync.h"
#include "aco_syscall.h"
#include "aco_specific.h"

#define DECLEAR_SYSCALL(name, rettype, ...)           \
    typedef rettype (*name##_syscall_f)(__VA_ARGS__); \
    static name##_syscall_f name##_syscall_hook = (name##_syscall_f)dlsym(RTLD_NEXT, #name);

#define HOOK_SYSCALL(name)                                               \
    if (name##_syscall_hook == NULL) {                                   \
        name##_syscall_hook = (name##_syscall_f)dlsym(RTLD_NEXT, #name); \
    }

DECLEAR_SYSCALL(close, int, int fd)
DECLEAR_SYSCALL(socket, int, int domain, int type, int protocol)
DECLEAR_SYSCALL(connect, int, int socket, const struct sockaddr *address, socklen_t address_len)

DECLEAR_SYSCALL(read, ssize_t, int fildes, void *buf, size_t nbyte)
DECLEAR_SYSCALL(write, ssize_t, int fildes, const void *buf, size_t nbyte)

DECLEAR_SYSCALL(sendto, ssize_t, int socket, const void *message, size_t length, int flags,
                const struct sockaddr *dest_addr, socklen_t dest_len)
DECLEAR_SYSCALL(recvfrom, ssize_t, int socket, void *buffer, size_t length, int flags,
                struct sockaddr *address, socklen_t *address_len)

DECLEAR_SYSCALL(send, ssize_t, int socket, const void *buffer, size_t length, int flags)
DECLEAR_SYSCALL(recv, ssize_t, int socket, void *buffer, size_t length, int flags)

DECLEAR_SYSCALL(poll, int, struct pollfd fds[], nfds_t nfds, int timeout)
DECLEAR_SYSCALL(setsockopt, int, int socket, int level, int option_name, const void *option_value,
                socklen_t option_len)

DECLEAR_SYSCALL(fcntl, int, int fildes, int cmd, ...)
DECLEAR_SYSCALL(localtime_r, struct tm *, const time_t *timep, struct tm *result)

DECLEAR_SYSCALL(pthread_getspecific, void *, pthread_key_t key)
DECLEAR_SYSCALL(pthread_setspecific, int, pthread_key_t key, const void *value)

DECLEAR_SYSCALL(setenv, int, const char *name, const char *value, int overwrite)
DECLEAR_SYSCALL(unsetenv, int, const char *name)
DECLEAR_SYSCALL(getenv, char *, const char *name)
DECLEAR_SYSCALL(gethostbyname, hostent *, const char *name)
DECLEAR_SYSCALL(__res_state, res_state)
DECLEAR_SYSCALL(__poll, int, struct pollfd fds[], nfds_t nfds, int timeout)

#if defined(__APPLE__) || defined(__FreeBSD__)
DECLEAR_SYSCALL(gethostbyname_r, int, const char *__restrict name)
#else
DECLEAR_SYSCALL(gethostbyname_r, int, const char *__restrict name, struct hostent *__restrict __result_buf,
                char *__restrict __buf, size_t __buflen, struct hostent **__restrict __result,
                int *__restrict __h_errnop)
#endif

// DECLEAR_SYSCALL(pthread_getspecific, void *, pthread_key_t key)
// DECLEAR_SYSCALL(pthread_getspecific, int, pthread_key_t key, const void
// *value)

// DECLEAR_SYSCALL(pthread_rwlock_rdlock, int, pthread_rwlock_t *rwlock)
// DECLEAR_SYSCALL(pthread_rwlock_wrlock, int, pthread_rwlock_t *rwlock)
// DECLEAR_SYSCALL(pthread_rwlock_unlock, int, pthread_rwlock_t *rwlock)

struct socketinfo {
    int user_flag;
    int domain;              // AF_LOCAL , AF_INET
    struct sockaddr_in dest; // maybe sockaddr_un;

    struct timeval read_timeout;
    struct timeval write_timeout;
};
static socketinfo *socketinfo_map[102400] = {0};
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static inline socketinfo *socketinfo_by_fd(int fd)
{
    if (fd > -1 && fd < (int)ARRAY_SIZE(socketinfo_map)) {
        return socketinfo_map[fd];
    }
    return NULL;
}

static inline socketinfo *socketinfo_new(int fd)
{
    if (fd > -1 && fd < (int)ARRAY_SIZE(socketinfo_map)) {
        socketinfo *info = (socketinfo *)calloc(1, sizeof(socketinfo));
        info->read_timeout.tv_sec = 1;
        info->write_timeout.tv_sec = 1;
        socketinfo_map[fd] = info;
        return info;
    }
    return NULL;
}

static inline void socketinfo_free_by_fd(int fd)
{
    if (fd > -1 && fd < (int)ARRAY_SIZE(socketinfo_map)) {
        socketinfo *info = socketinfo_map[fd];
        if (info != NULL) {
            socketinfo_map[fd] = NULL;
            free(info);
        }
    }
    return;
}

int socket(int domain, int type, int protocol)
{
    HOOK_SYSCALL(socket);

    if (!aco_syscall_hooked(aco_self())) {
        return socket_syscall_hook(domain, type, protocol);
    }
    int fd = socket_syscall_hook(domain, type, protocol);
    if (aco_likely(fd >= 0)) {
        socketinfo *info = socketinfo_new(fd);
        if (info) {
            info->domain = domain;
        }

        fcntl(fd, F_SETFL, fcntl_syscall_hook(fd, F_GETFL, 0));
    }

    return fd;
}

int aco_accept(int fd, struct sockaddr *addr, socklen_t *len)
{
    int sock = accept(fd, addr, len);
    if (aco_likely(sock >= 0)) {
        socketinfo_new(sock);
    }
    return sock;
}

int connect(int fd, const struct sockaddr *address, socklen_t address_len)
{
    HOOK_SYSCALL(connect);

    if (!aco_syscall_hooked(aco_self())) {
        return connect_syscall_hook(fd, address, address_len);
    }

    // 1.sys call
    int ret = connect_syscall_hook(fd, address, address_len);

    socketinfo *info = socketinfo_by_fd(fd);
    if (!info) return ret;

    if (sizeof(info->dest) >= address_len) {
        memcpy(&(info->dest), address, (int)address_len);
    }
    if (O_NONBLOCK & info->user_flag) {
        return ret;
    }

    if (!(ret < 0 && errno == EINPROGRESS)) {
        return ret;
    }

    // 2.wait
    struct pollfd pf = {0};
    for (int i = 0; i < 3; i++) { // 25s * 3 = 75s
        memset(&pf, 0, sizeof(pf));
        pf.fd = fd;
        pf.events = (POLLOUT | POLLERR | POLLHUP);

        if ((ret = poll(&pf, 1, 25000)) == 1) {
            break;
        }
    }

    if (pf.revents & POLLOUT) { // connect succ
        // 3.check getsockopt ret
        int err = 0;
        socklen_t errlen = sizeof(err);
        ret = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &errlen);
        if (ret < 0) {
            return ret;
        } else if (err != 0) {
            errno = err;
            return -1;
        }
        errno = 0;
        return 0;
    }
    errno = ETIMEDOUT;

    return ret;
}

int close(int fd)
{
    HOOK_SYSCALL(close);

    if (!aco_syscall_hooked(aco_self())) {
        return close_syscall_hook(fd);
    }

    socketinfo_free_by_fd(fd);
    return close_syscall_hook(fd);
}

ssize_t read(int fd, void *buf, size_t nbyte)
{
    HOOK_SYSCALL(read);

    if (!aco_syscall_hooked(aco_self())) {
        return read_syscall_hook(fd, buf, nbyte);
    }
    socketinfo *info = socketinfo_by_fd(fd);

    if (!info || (O_NONBLOCK & info->user_flag)) {
        return read_syscall_hook(fd, buf, nbyte);
    }

    int timeout = (info->read_timeout.tv_sec * 1000) + (info->read_timeout.tv_usec / 1000);
    struct pollfd pf = {.fd = fd, .events = POLLIN | POLLERR | POLLHUP};
    poll(&pf, 1, timeout);

    return read_syscall_hook(fd, (char *)buf, nbyte);
}

ssize_t write(int fd, const void *buf, size_t nbyte)
{
    HOOK_SYSCALL(write);

    if (!aco_syscall_hooked(aco_self())) {
        return write_syscall_hook(fd, buf, nbyte);
    }

    socketinfo *info = socketinfo_by_fd(fd);
    if (!info || (O_NONBLOCK & info->user_flag)) {
        ssize_t ret = write_syscall_hook(fd, buf, nbyte);
        return ret;
    }
    size_t wrotelen = 0;
    int timeout = (info->write_timeout.tv_sec * 1000) + (info->write_timeout.tv_usec / 1000);
    ssize_t writeret = write_syscall_hook(fd, (const char *)buf + wrotelen, nbyte - wrotelen);

    if (writeret == 0) {
        return writeret;
    } else {
        wrotelen += writeret;

        struct pollfd pf = {0};
        while (wrotelen < nbyte) {
            pf.fd = fd;
            pf.events = (POLLOUT | POLLERR | POLLHUP);
            poll(&pf, 1, timeout);

            if ((writeret = write_syscall_hook(fd, (const char *)buf + wrotelen, nbyte - wrotelen)) <= 0) {
                break;
            }
            wrotelen += writeret;
        }
        if (writeret <= 0 && wrotelen == 0) {
            return writeret;
        }

        return wrotelen;
    }
}

ssize_t sendto(int socket, const void *message, size_t length, int flags, const struct sockaddr *dest_addr,
               socklen_t dest_len)
{
    HOOK_SYSCALL(sendto);

    if (!aco_syscall_hooked(aco_self())) {
        return sendto_syscall_hook(socket, message, length, flags, dest_addr, dest_len);
    }

    socketinfo *info = socketinfo_by_fd(socket);
    if (!info || (O_NONBLOCK & info->user_flag)) {
        return sendto_syscall_hook(socket, message, length, flags, dest_addr, dest_len);
    } else {
        ssize_t ret = sendto_syscall_hook(socket, message, length, flags, dest_addr, dest_len);
        if (ret < 0 && EAGAIN == errno) {
            int timeout = (info->write_timeout.tv_sec * 1000) + (info->write_timeout.tv_usec / 1000);
            struct pollfd pf = {.fd = socket, .events = (POLLOUT | POLLERR | POLLHUP)};
            poll(&pf, 1, timeout);

            ret = sendto_syscall_hook(socket, message, length, flags, dest_addr, dest_len);
        }

        return ret;
    }
}

ssize_t recvfrom(int socket, void *buffer, size_t length, int flags, struct sockaddr *address,
                 socklen_t *address_len)
{
    HOOK_SYSCALL(recvfrom);

    if (!aco_syscall_hooked(aco_self())) {
        return recvfrom_syscall_hook(socket, buffer, length, flags, address, address_len);
    }

    socketinfo *info = socketinfo_by_fd(socket);
    if (!info || (O_NONBLOCK & info->user_flag)) {
        return recvfrom_syscall_hook(socket, buffer, length, flags, address, address_len);
    } else {
        int timeout = (info->read_timeout.tv_sec * 1000) + (info->read_timeout.tv_usec / 1000);
        struct pollfd pf = {.fd = socket, .events = (POLLIN | POLLERR | POLLHUP)};
        poll(&pf, 1, timeout);

        return recvfrom_syscall_hook(socket, buffer, length, flags, address, address_len);
    }
}

ssize_t send(int socket, const void *buffer, size_t length, int flags)
{
    HOOK_SYSCALL(send);

    if (!aco_syscall_hooked(aco_self())) {
        return send_syscall_hook(socket, buffer, length, flags);
    }
    socketinfo *info = socketinfo_by_fd(socket);

    if (!info || (O_NONBLOCK & info->user_flag)) {
        return send_syscall_hook(socket, buffer, length, flags);
    }
    size_t wrotelen = 0;
    int timeout = (info->write_timeout.tv_sec * 1000) + (info->write_timeout.tv_usec / 1000);

    ssize_t writeret = send_syscall_hook(socket, buffer, length, flags);
    if (writeret == 0) {
        return writeret;
    } else {
        wrotelen += writeret;

        struct pollfd pf = {0};
        while (wrotelen < length) {
            pf.fd = socket;
            pf.events = (POLLOUT | POLLERR | POLLHUP);
            poll(&pf, 1, timeout);

            if ((writeret =
                     send_syscall_hook(socket, (const char *)buffer + wrotelen, length - wrotelen, flags))
                <= 0) {
                break;
            }
            wrotelen += writeret;
        }
        if (writeret <= 0 && wrotelen == 0) {
            return writeret;
        }
        return wrotelen;
    }
}

ssize_t recv(int socket, void *buffer, size_t length, int flags)
{
    HOOK_SYSCALL(recv);

    if (!aco_syscall_hooked(aco_self())) {
        return recv_syscall_hook(socket, buffer, length, flags);
    } else {
        socketinfo *info = socketinfo_by_fd(socket);
        if (!info || (O_NONBLOCK & info->user_flag)) {
            return recv_syscall_hook(socket, buffer, length, flags);
        }

        int timeout = (info->read_timeout.tv_sec * 1000) + (info->read_timeout.tv_usec / 1000);
        struct pollfd pf = {.fd = socket, .events = POLLIN | POLLERR | POLLHUP};
        poll(&pf, 1, timeout);

        return recv_syscall_hook(socket, buffer, length, flags);
    }
}

int setsockopt(int fd, int level, int option_name, const void *option_value, socklen_t option_len)
{
    HOOK_SYSCALL(setsockopt);

    if (!aco_syscall_hooked(aco_self())) {
        return setsockopt_syscall_hook(fd, level, option_name, option_value, option_len);
    }
    socketinfo *info = socketinfo_by_fd(fd);

    if (info && SOL_SOCKET == level) {
        const struct timeval *val = (const struct timeval *)option_value;
        if (SO_RCVTIMEO == option_name) {
            memcpy(&info->read_timeout, val, sizeof(*val));
        } else if (SO_SNDTIMEO == option_name) {
            memcpy(&info->write_timeout, val, sizeof(*val));
        }
    }
    return setsockopt_syscall_hook(fd, level, option_name, option_value, option_len);
}

int fcntl(int fildes, int cmd, ...)
{
    HOOK_SYSCALL(fcntl);

    if (fildes < 0) {
        return __LINE__;
    }

    va_list arg_list;
    va_start(arg_list, cmd);

    int ret = -1;
    socketinfo *info = socketinfo_by_fd(fildes);
    switch (cmd) {
        case F_DUPFD: {
            int param = va_arg(arg_list, int);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
        case F_GETFD: {
            ret = fcntl_syscall_hook(fildes, cmd);
            break;
        }
        case F_SETFD: {
            int param = va_arg(arg_list, int);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
        case F_GETFL: {
            ret = fcntl_syscall_hook(fildes, cmd);
            if (info && !(info->user_flag & O_NONBLOCK)) {
                ret = ret & (~O_NONBLOCK);
            }
            break;
        }
        case F_SETFL: {
            int param = va_arg(arg_list, int);
            int flag = param;
            if (aco_syscall_hooked(aco_self()) && info) {
                flag |= O_NONBLOCK;
            }
            ret = fcntl_syscall_hook(fildes, cmd, flag);
            if (0 == ret && info) {
                info->user_flag = param;
            }
            break;
        }
        case F_GETOWN: {
            ret = fcntl_syscall_hook(fildes, cmd);
            break;
        }
        case F_SETOWN: {
            int param = va_arg(arg_list, int);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
        case F_GETLK: {
            struct flock *param = va_arg(arg_list, struct flock *);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
        case F_SETLK: {
            struct flock *param = va_arg(arg_list, struct flock *);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
        case F_SETLKW: {
            struct flock *param = va_arg(arg_list, struct flock *);
            ret = fcntl_syscall_hook(fildes, cmd, param);
            break;
        }
    }

    va_end(arg_list);

    return ret;
}

// FIXME
typedef struct aco_epoll_st aco_epoll_t;
static int aco_poll_inner(aco_epoll_t *ctx, struct pollfd fds[], nfds_t nfds, int timeout,
                          poll_syscall_f pollfunc)
{
    (void)ctx, (void)fds, (void)nfds, (void)timeout, (void)pollfunc;
    return 0;
}

static aco_epoll_t *aco_get_epoll()
{
    return NULL;
}

int poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    HOOK_SYSCALL(poll);

    if (!aco_syscall_hooked(aco_self()) || timeout == 0) {
        return poll_syscall_hook(fds, nfds, timeout);
    }

    nfds_t nfds_merge = 0;
    pollfd *fds_merge = NULL;
    std::map<int, int> m; // fd --> idx
    std::map<int, int>::iterator it;
    if (nfds > 1) {
        fds_merge = (pollfd *)malloc(sizeof(pollfd) * nfds);
        for (size_t i = 0; i < nfds; i++) {
            if ((it = m.find(fds[i].fd)) == m.end()) {
                fds_merge[nfds_merge] = fds[i];
                m[fds[i].fd] = nfds_merge;
                nfds_merge++;
            } else {
                int j = it->second;
                fds_merge[j].events |= fds[i].events; // merge in j slot
            }
        }
    }

    int ret = 0;
    if (nfds_merge == nfds || nfds == 1) {
        ret = aco_poll_inner(aco_get_epoll(), fds, nfds, timeout, poll_syscall_hook);
    } else {
        ret = aco_poll_inner(aco_get_epoll(), fds_merge, nfds_merge, timeout, poll_syscall_hook);
        if (ret > 0) {
            for (size_t i = 0; i < nfds; i++) {
                it = m.find(fds[i].fd);
                if (it != m.end()) {
                    int j = it->second;
                    fds[i].revents = fds_merge[j].revents & fds[i].events;
                }
            }
        }
    }
    free(fds_merge);
    return ret;
}

/* enviroment */
static struct aco_st::envlist __acoenv = {0};

static aco_st::envlist *aco_envlist_dup(const aco_st::envlist *src)
{
    aco_st::envlist *list = (aco_st::envlist *)calloc(sizeof(aco_st::envlist), 1);
    if (src->size) {
        list->pairs = (aco_st::envlist::env *)calloc(sizeof(aco_st::envlist::env) * src->size, 1);
        memcpy(list->pairs, src->pairs, sizeof(aco_st::envlist::env) * src->size);
        list->size = src->size;
    }
    return list;
}

static int aco_env_cmp(const void *a, const void *b)
{
    return strcmp(((const aco_st::envlist::env *)a)->name, ((const aco_st::envlist::env *)b)->name);
}

void aco_envlist_set(const char *name[], size_t size)
{
    if (__acoenv.pairs) {
        return;
    }
    __acoenv.pairs = (aco_st::envlist::env *)calloc(1, sizeof(aco_st::envlist::env) * size);
    if (__acoenv.pairs == NULL) {
        return;
    }

    for (size_t i = 0; i < size; i++) {
        if (name[i] && name[i][0]) {
            __acoenv.pairs[__acoenv.size++].name = strdup(name[i]);
        }
    }
    if (__acoenv.size > 1) {
        qsort(__acoenv.pairs, __acoenv.size, sizeof(aco_st::envlist::env), aco_env_cmp);
        aco_st::envlist::env *info = __acoenv.pairs;
        aco_st::envlist::env *lq = __acoenv.pairs + 1;
        for (size_t i = 1; i < __acoenv.size; i++) {
            if (strcmp(info->name, lq->name)) {
                ++info;
                if (lq != info) {
                    *info = *lq;
                }
            }
            ++lq;
        }
        __acoenv.size = info - __acoenv.pairs + 1;
    }
}

int setenv(const char *name, const char *value, int overwrite)
{
    HOOK_SYSCALL(setenv)

    if (aco_syscall_hooked(aco_self()) && __acoenv.pairs) {
        aco_t *self = aco_self();
        if (self) {
            if (!self->enviros) {
                self->enviros = aco_envlist_dup(&__acoenv);
                aco_assert(self->enviros != NULL);
            }

#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-qual"
#endif
            aco_st::envlist::env env = {(char *)name, 0};
#ifdef __GNUC__
    #pragma GCC diagnostic pop
#elif defined(__clang__)
    #pragma clang diagnostic pop
#endif
            aco_st::envlist *arr = (aco_st::envlist *)self->enviros;
            aco_st::envlist::env *e =
                (aco_st::envlist::env *)bsearch(&env, arr->pairs, arr->size, sizeof(env), aco_env_cmp);
            if (e) {
                if (overwrite || !e->value) {
                    if (e->value) free(e->value);
                    e->value = (value ? strdup(value) : 0);
                }
                return 0;
            }
        }
    }

    return setenv_syscall_hook(name, value, overwrite);
}

int unsetenv(const char *name)
{
    HOOK_SYSCALL(unsetenv)

    if (aco_syscall_hooked(aco_self()) && __acoenv.pairs) {
        aco_t *self = aco_self();
        if (self) {
            if (!self->enviros) {
                self->enviros = aco_envlist_dup(&__acoenv);
                aco_assert(self->enviros != NULL);
            }

#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-qual"
#endif
            aco_st::envlist::env env = {(char *)name, 0};
#ifdef __GNUC__
    #pragma GCC diagnostic pop
#elif defined(__clang__)
    #pragma clang diagnostic pop
#endif
            aco_st::envlist *arr = (aco_st::envlist *)self->enviros;
            aco_st::envlist::env *e =
                (aco_st::envlist::env *)bsearch(&env, arr->pairs, arr->size, sizeof(env), aco_env_cmp);

            if (e) {
                if (e->value) {
                    free(e->value);
                    e->value = 0;
                }
                return 0;
            }
        }
    }
    return unsetenv_syscall_hook(name);
}

char *getenv(const char *name)
{
    HOOK_SYSCALL(getenv)
    if (aco_syscall_hooked(aco_self()) && __acoenv.pairs) {
        aco_t *self = aco_self();
        if (self) {
            if (!self->enviros) {
                self->enviros = aco_envlist_dup(&__acoenv);
                aco_assert(self->enviros != NULL);
            }

#ifdef __GNUC__
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
#elif defined(__clang__)
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcast-qual"
#endif
            aco_st::envlist::env env = {(char *)name, 0};
#ifdef __GNUC__
    #pragma GCC diagnostic pop
#elif defined(__clang__)
    #pragma clang diagnostic pop
#endif
            aco_st::envlist *arr = (aco_st::envlist *)(self->enviros);
            aco_st::envlist::env *e =
                (aco_st::envlist::env *)bsearch(&env, arr->pairs, arr->size, sizeof(env), aco_env_cmp);

            if (e) {
                return e->value;
            }
        }
    }

    return getenv_syscall_hook(name);
}


struct res_state_wrap {
    struct __res_state state;
};
ACO_SPECIFIC_DEFINE(res_state_wrap, __aco_state_wrap);

extern "C" {
res_state __res_state()
{
    HOOK_SYSCALL(__res_state);

    if (!aco_syscall_hooked(aco_self())) {
        return __res_state_syscall_hook();
    }

    return &(__aco_state_wrap->state);
}

int __poll(struct pollfd fds[], nfds_t nfds, int timeout)
{
    return poll(fds, nfds, timeout);
}
}

#if !defined(__APPLE__) && !defined(__FreeBSD__)
struct hostbuf_wrap {
    struct hostent host;
    char *buffer;
    size_t iBufferSize;
    int host_errno;
};
ACO_SPECIFIC_DEFINE(hostbuf_wrap, __aco_hostbuf_wrap);

struct hostent *aco_gethostbyname(const char *name)
{
    if (!name) {
        return NULL;
    }

    if (__aco_hostbuf_wrap->buffer && __aco_hostbuf_wrap->iBufferSize > 1024) {
        free(__aco_hostbuf_wrap->buffer);
        __aco_hostbuf_wrap->buffer = NULL;
    }
    if (!__aco_hostbuf_wrap->buffer) {
        __aco_hostbuf_wrap->buffer = (char *)malloc(1024);
        __aco_hostbuf_wrap->iBufferSize = 1024;
    }

    struct hostent *host = &__aco_hostbuf_wrap->host;
    struct hostent *result = NULL;
    int *h_errnop = &(__aco_hostbuf_wrap->host_errno);

    int ret = -1;
    while (ret = gethostbyname_r(name, host, __aco_hostbuf_wrap->buffer, __aco_hostbuf_wrap->iBufferSize,
                                 &result, h_errnop)
                     == ERANGE
                 && *h_errnop == NETDB_INTERNAL) {
        free(__aco_hostbuf_wrap->buffer);
        __aco_hostbuf_wrap->iBufferSize = __aco_hostbuf_wrap->iBufferSize * 2;
        __aco_hostbuf_wrap->buffer = (char *)malloc(__aco_hostbuf_wrap->iBufferSize);
    }

    if (ret == 0 && (host == result)) {
        return host;
    }
    return NULL;
}
#endif

struct hostent *aco_gethostbyname(const char *name);

struct hostent *gethostbyname(const char *name)
{
    HOOK_SYSCALL(gethostbyname);

#if defined(__APPLE__) || defined(__FreeBSD__)
    return gethostbyname_syscall_hook(name);
#else
    if (!aco_syscall_hooked(aco_self())) {
        return gethostbyname_syscall_hook(name);
    }
    return aco_gethostbyname(name);
#endif
}

int aco_gethostbyname_r(const char *__restrict name, struct hostent *__restrict __result_buf,
                        char *__restrict __buf, size_t __buflen, struct hostent **__restrict __result,
                        int *__restrict __h_errnop)
{
    static __thread aco_mutex *tls_leaky_dns_lock = NULL;
    if (tls_leaky_dns_lock == NULL) {
        tls_leaky_dns_lock = new aco_mutex();
    }
    aco_lock_guard auto_lock(*tls_leaky_dns_lock);
#if defined(__APPLE__) || defined(__FreeBSD__)
    (void)__result_buf, (void)__buf, (void)__buflen, (void)__result, (void)__h_errnop;
    return gethostbyname_r_syscall_hook(name);
#else
    return gethostbyname_r_syscall_hook(name, __result_buf, __buf, __buflen, __result, __h_errnop);
#endif
}

int gethostbyname_r(const char *__restrict name, struct hostent *__restrict __result_buf,
                    char *__restrict __buf, size_t __buflen, struct hostent **__restrict __result,
                    int *__restrict __h_errnop)
{
    HOOK_SYSCALL(gethostbyname_r);

#if defined(__APPLE__) || defined(__FreeBSD__)
    (void)__result_buf, (void)__buf, (void)__buflen, (void)__result, (void)__h_errnop;
    return gethostbyname_r_syscall_hook(name);
#else
    if (!aco_syscall_hooked(aco_self())) {
        return gethostbyname_r_syscall_hook(name, __result_buf, __buf, __buflen, __result, __h_errnop);
    }

    return aco_gethostbyname_r(name, __result_buf, __buf, __buflen, __result, __h_errnop);
#endif
}
