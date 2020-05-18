

#ifndef _LIBCITADEL_COMMON_H
#define _LIBCITADEL_COMMON_H

#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* malloc, free, rand */
#include <linux/types.h>
#include <stdint.h>

#include "citadel.h"

extern char* to_hexstring(unsigned char *buf, unsigned int len);
extern void print_hex(unsigned char *buf, size_t len);
#endif