
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

/***/

#define CITADEL_ENCLAVE_STD_PREFIX_ "\033[0;93m[♜]\033[0m "
#define CITADEL_ENCLAVE_ERR_PREFIX_ "\033[0;31m[♜]\033[0m "
#define CITADEL_ENCLAVE_PERF_PREFIX_ "\033[0;33m[♜] \033[1;37mPerformance:\033[0m "

extern "C" inline void _enclave_printf(const char *format, ...)
{
#if CITADEL_DEBUG
    char buffer[10000]; // TODO arbitrary.
    va_list args;
    va_start (args, format);
    vsnprintf (buffer, 10000 - 1, format, args);
    va_end (args);
    ocall_print(buffer);
#endif
}

#define enclave_printf(format, args...) (_enclave_printf(CITADEL_ENCLAVE_STD_PREFIX_ format, ## args));
#define enclave_perror(format, args...) (_enclave_printf(CITADEL_ENCLAVE_ERR_PREFIX_ format, ## args));
#define enclave_perf(format, args...) (_enclave_printf(CITADEL_ENCLAVE_PERF_PREFIX_ format, ## args));

#endif
