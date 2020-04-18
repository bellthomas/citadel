
#include "includes/common.h"

char* to_hexstring(unsigned char *buf, unsigned int len) {
    char   *out;
	size_t  i;

    if (buf == NULL || len == 0) return NULL;

    out = kmalloc(2*len+1, GFP_KERNEL);
    for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[buf[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[buf[i] & 0x0F];
	}
    out[len*2] = '\0';
    return out;
}