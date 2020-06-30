

#ifndef _LIBCITADEL_IPC_H
#define _LIBCITADEL_IPC_H



// #include <nng/nng.h>
// #include <nng/protocol/reqrep0/rep.h>
// #include <nng/protocol/reqrep0/req.h>
// #include <nng/transport/ipc/ipc.h>

#include <sys/socket.h>

#include "citadel.h"

typedef struct ucred ucred_t;

extern bool ipc_transaction(unsigned char *request, size_t length);

#endif