

#ifndef _U_ENCLAVE_TRM_SOCKET_H
#define _U_ENCLAVE_TRM_SOCKET_H

#include <pthread.h>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

#define CITADEL_IPC_FILE "/run/citadel.socket"
#define CITADEL_IPC_ADDRESS "ipc://" CITADEL_IPC_FILE

extern int initialise_socket(void);
extern int close_socket(void);

#endif
