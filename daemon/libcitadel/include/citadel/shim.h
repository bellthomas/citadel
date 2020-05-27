

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _LIBCITADEL_SHIM_H
#define _LIBCITADEL_SHIM_H

extern pid_t c_fork(void);
extern int c_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int c_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);

#endif

#ifdef __cplusplus
}
#endif