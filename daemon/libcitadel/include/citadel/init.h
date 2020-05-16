


#ifndef _LIBCITADEL_INIT_H
#define _LIBCITADEL_INIT_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h> 
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

#include "citadel.h"

#define CITADEL_KEY_PID_MULTIPLIER 137

extern int citadel_init(void);

#endif