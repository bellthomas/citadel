
#ifndef TRM_ENCLAVE_H_
#define TRM_ENCLAVE_H_

#include "Enclave_t.h"
#include <stdio.h>
#include <sgx_trts.h>

#include "../asm/interface.h"
#include "../crypto/crypto.h"

extern void print_hex(unsigned char *buf, unsigned int len);

#endif
