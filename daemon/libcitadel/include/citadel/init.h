


#ifndef _LIBCITADEL_INIT_H
#define _LIBCITADEL_INIT_H

#include <stdlib.h>
#include <stdio.h>
#include <time.h> 
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <stdint.h>

#include "citadel.h"

#define CITADEL_KEY_PID_MULTIPLIER 137

extern const char *get_ptoken(void);
extern const char *get_signed_ptoken(void);
extern const int32_t get_citadel_pid(void);

extern bool citadel_init(void);

#endif