

#ifndef _U_ENCLAVE_TRM_SOCKET_H
#define _U_ENCLAVE_TRM_SOCKET_H

#include <nng/nng.h>
#include <pthread.h>
#include <cstring>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>

extern int initialise_socket(void);
extern int close_socket(void);

#endif
