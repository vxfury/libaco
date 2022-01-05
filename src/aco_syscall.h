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
