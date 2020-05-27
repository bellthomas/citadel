#include <sys/types.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>

#include "../include/citadel/shim.h"
#include "../include/citadel/citadel.h"

pid_t c_fork(void) {
    pid_t res = fork();
    if (res == 0) {
        // Child process.
        bool citadel_ready = citadel_init();
        if (!citadel_ready) {
            citadel_printf("[Shim] Citadel failed to init.\n");
            // exit(1);
        }
    }
    return res;
}

int c_bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
	bool socket_allowed = citadel_socket(sockfd, (struct sockaddr *)addr);
    if (socket_allowed) {
        int res = bind(sockfd, addr, addrlen);
        if (res >= 0 && addr->sa_family == AF_UNIX) {
            struct sockaddr_un *local_addr = (struct sockaddr_un *)addr;

            // TODO fails here
            bool citadel_file_create_ret = citadel_file_claim_force(local_addr->sun_path, strlen(local_addr->sun_path)+1);
            if (!citadel_file_create_ret) {
                unlink(local_addr->sun_path);
                return -EPERM;
            }
        }
        return res;
    }
    return -EPERM;
}

int c_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    bool socket_allowed = citadel_socket(sockfd, (struct sockaddr *)addr);
    if (socket_allowed) {
        if (addr->sa_family == AF_UNIX) {
            struct sockaddr_un *local_addr = (struct sockaddr_un *)addr;
            bool citadel_file_create_ret = citadel_file_open(local_addr->sun_path, strlen(local_addr->sun_path)+1);
            if (!citadel_file_create_ret) return -EPERM;
        }
        return connect(sockfd, addr, addrlen);
    }
    return -EPERM;
}