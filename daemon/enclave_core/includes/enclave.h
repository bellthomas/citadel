
#ifndef TRM_ENCLAVE_H_
#define TRM_ENCLAVE_H_

#include "Enclave_t.h"
#include <stdio.h>
#include <sgx_trts.h>

#include "../asm/interface.h"
#include "../crypto/crypto.h"
#include "lsm_communication.h"
#include "userspace_io.h"

extern void print_hex(unsigned char *buf, unsigned int len);

#endif
