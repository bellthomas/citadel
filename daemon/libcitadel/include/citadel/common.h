

#ifndef _LIBCITADEL_COMMON_H
#define _LIBCITADEL_COMMON_H

#include <stdio.h>      /* printf, scanf, NULL */
#include <stdlib.h>     /* malloc, free, rand */
#include <linux/types.h>
#include <stdint.h>

extern char* to_hexstring(unsigned char *buf, unsigned int len);

#endif