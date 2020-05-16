


#ifndef _LIBCITADEL_INIT_H
#define _LIBCITADEL_INIT_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h> 
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "_trm_shared.h"
#include "common.h"

#define CITADEL_KEY_PID_MULTIPLIER 137

extern int citadel_init(void);

#endif