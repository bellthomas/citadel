#include "includes/socket.h"

static pthread_t thid;

void *socket_thread(void *arg) {
    char *ret;

    sleep(5); // seconds
    strcpy(ret, "This is a test");
    pthread_exit(ret);
}


int initialise_socket(void) {
    if (pthread_create(&thid, NULL, socket_thread, NULL) != 0) {
        perror("pthread_create() error");
        return -EIO;
    }

    return 0;
}

int close_socket(void) {
    void *ret;
    if (pthread_join(thid, &ret) != 0) {
        perror("pthread_join() error");
        return -EIO;
    }
    return 0;
}