#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "../include/citadel/shim.h"
#include "../include/citadel/citadel.h"

pid_t c_fork(void) {
    pid_t res = fork();
    if (res == 0) {
        // Child process.
        if (!citadel_init())
            citadel_printf("[Shim] Citadel failed to init.\n");
    }
    return res;
}

int c_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    bool tainted = true;
    if (citadel_socket(sockfd, (struct sockaddr *)addr, &tainted)) {
        int res = bind(sockfd, addr, addrlen);
        if (tainted && res >= 0 && addr->sa_family == AF_UNIX) {
            struct sockaddr_un *local_addr = (struct sockaddr_un *)addr;
            if (!citadel_file_claim_force(local_addr->sun_path, strlen(local_addr->sun_path)+1)) {
                unlink(local_addr->sun_path);
                return -EPERM;
            }
        }
        return res;
    }
    return -EPERM;
}

int c_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    bool tainted = true;
    if (citadel_socket(sockfd, (struct sockaddr *)addr, &tainted)) {
        if (tainted && addr->sa_family == AF_UNIX) {
            struct sockaddr_un *local_addr = (struct sockaddr_un *)addr;
            if (!citadel_file_open(local_addr->sun_path, strlen(local_addr->sun_path)+1)) 
                return -EPERM;
        }
        return connect(sockfd, addr, addrlen);
    }
    return -EPERM;
}

int c_listen(int sockfd, int backlog) {
    if (citadel_validate_socket_fd(sockfd, NULL, NULL, NULL))
        return listen(sockfd, backlog);
    return -EPERM;
}

int c_mkfifo(const char *pathname, mode_t mode) {
    int res = mkfifo(pathname, mode);
    if (res >= 0 && !citadel_file_claim_force(pathname, strlen(pathname)+1)) {
        unlink(pathname);
        return -EPERM;
    }
    return res;
}


int c_open(const char *pathname, int oflag) {
    // bool citadel_file_create_ret = citadel_file_open((char*)myfifo, sizeof(myfifo));
		// if (!citadel_file_create_ret) {
		// 	printf("Child failed to open file.\n");
		// 	return;
		// } else 
    if (!citadel_file_open(pathname, strlen(pathname)+1))
        return -EPERM;
    return open(pathname, oflag);
}

FILE *c_fopen(const char *pathname, const char *mode) {
    if (!citadel_file_open(pathname, strlen(pathname)+1))
        return (void*)(-EPERM);
    return fopen(pathname, mode);
}
// int open(const char *path, int oflag, .../*,mode_t mode */);
// int openat(int fd, const char *path, int oflag, ...);
// int creat(const char *path, mode_t mode);
// FILE *fopen(const char *restrict filename, const char *restrict mode);
// FILE *fopen(const char *pathname, const char *mode);

//        FILE *fdopen(int fd, const char *mode);

//        FILE *freopen(const char *pathname, const char *mode, FILE *stream);