
#ifndef TRM_ENCLAVE_H_
#define TRM_ENCLAVE_H_

#include "Enclave_t.h"
#include <stdio.h>
#include <sgx_trts.h>

#include "../asm/interface.h"
#include "../crypto/crypto.h"
#include "lsm_communication.h"
#include "userspace_io.h"

extern void _print_hex(bool embedded, unsigned char *buf, unsigned int len);

/***/

#define MUTE_ASM true
#define CITADEL_ENCLAVE_STD_PREFIX_ "\033[0;93m[♜]\033[0m "
#define CITADEL_ENCLAVE_ERR_PREFIX_ "\033[0;31m[♜]\033[0m "
#define CITADEL_ENCLAVE_PERF_PREFIX_ "\033[0;33m[♜] \033[1;37mPerformance:\033[0m "
#define CITADEL_ENCLAVE_ASM_PREFIX_ "\033[1;35m[Ω]\033[0m "

extern "C" inline void _enclave_printf(bool quiet, const char *format, ...)
{
#if CITADEL_DEBUG
    char buffer[10000]; // TODO arbitrary.
    if (quiet) return;
    va_list args;
    va_start (args, format);
    vsnprintf (buffer, 10000 - 1, format, args);
    va_end (args);
    ocall_print(buffer);
#endif
}

#define enclave_printf(format, args...) (_enclave_printf(false, CITADEL_ENCLAVE_STD_PREFIX_ format, ## args));
#define enclave_perror(format, args...) (_enclave_printf(false, CITADEL_ENCLAVE_ERR_PREFIX_ format, ## args));
#define enclave_perf(format, args...) (_enclave_printf(false, CITADEL_ENCLAVE_PERF_PREFIX_ format, ## args));
#define asm_printf(format, args...) (_enclave_printf(MUTE_ASM, CITADEL_ENCLAVE_ASM_PREFIX_ format, ## args));
#define print_hex(buf, len) (_print_hex(false, buf, len));
#define asm_hex(buf, len) (_print_hex(true, buf, len));

#endif
