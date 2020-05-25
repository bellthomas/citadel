

#ifndef _U_ENCLAVE_TRM_SOCKET_H
#define _U_ENCLAVE_TRM_SOCKET_H

#include <pthread.h>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

// #include <nng/nng.h>
// #include <nng/protocol/reqrep0/rep.h>
// #include <nng/protocol/reqrep0/req.h>
// #include <nng/transport/ipc/ipc.h>

#include "app.h"

#define SOCKET_NON_BLOCKING 0
#define SOCKET_PERFORMANCE 1

extern int initialise_socket(void);
extern int close_socket(void);

#endif
