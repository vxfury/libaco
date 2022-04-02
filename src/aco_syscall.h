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

#ifndef ACO_SYSCALL_H
#define ACO_SYSCALL_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/syscall.h>
#include <sys/un.h>

#include <dlfcn.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>

#include <netinet/in.h>
#include <errno.h>
#include <time.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <pthread.h>

#include <resolv.h>
#include <netdb.h>

#include <time.h>

// res_state __res_state();

// int __poll(struct pollfd fds[], nfds_t nfds, int timeout);

int aco_gethostbyname_r(const char *__restrict name, struct hostent *__restrict __result_buf,
                        char *__restrict __buf, size_t __buflen, struct hostent **__restrict __result,
                        int *__restrict __h_errnop);

int aco_accept(int fd, struct sockaddr *addr, socklen_t *len);

void aco_envlist_set(const char *name[], size_t size);

#endif
