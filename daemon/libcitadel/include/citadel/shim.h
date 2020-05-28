

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _LIBCITADEL_SHIM_H
#define _LIBCITADEL_SHIM_H

#include <stdio.h>

extern pid_t c_fork(void);
extern int c_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int c_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int c_mkfifo(const char *pathname, mode_t mode);
extern int c_open(const char* pathname, int oflag);
extern FILE *c_fopen(const char *pathname, const char *mode);

#endif

#ifdef __cplusplus
}
#endif