

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _LIBCITADEL_SHIM_H
#define _LIBCITADEL_SHIM_H

#include <stdio.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdbool.h>
#include <stdint.h>

extern pid_t c_fork(void);
extern int c_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int c_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
extern int c_listen(int sockfd, int backlog);
extern int c_mkfifo(const char *pathname, mode_t mode);
extern int c_open(const char* pathname, int oflag, mode_t mode);
extern int c_close(int fd);
extern FILE *c_fopen(const char *pathname, const char *mode);
extern int c_shmget(key_t key, size_t size, int shmflg);
extern void *c_shmat(int shmid, const void *shmaddr, int shmflg);
extern int c_shmctl(int shmid, int cmd, struct shmid_ds *buf);
extern ssize_t c_read(int fildes, void *buf, size_t nbyte);
extern ssize_t c_write(int fd, const void *buf, size_t count);
extern ssize_t c_pread(int fd, void *buf, size_t count, off_t offset);
extern ssize_t c_pwrite(int fd, const void *buf, size_t count, off_t offset);
extern ssize_t c_send(int socket, const void *buffer, size_t length, int flags);
extern ssize_t c_recv(int sockfd, void *buf, size_t len, int flags);
extern ssize_t c_writev(int fd, const struct iovec *iov, int iovcnt);
extern ssize_t c_sendfile(int out_fd, int in_fd, off_t *offset, size_t count);
extern int c_socketpair(int domain, int type, int protocol, int sv[2]);

#endif

#ifdef __cplusplus
}
#endif