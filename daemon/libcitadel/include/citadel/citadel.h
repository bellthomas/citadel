

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _LIBCITADEL_H
#define _LIBCITADEL_H

#include <stdint.h>
#include <stdbool.h>
// #include <nng/nng.h>

#include "_citadel_shared.h"
#include "common.h"
#include "init.h"
#include "ipc.h"
#include "file.h"
#include "socket.h"

#define _LIBCITADEL_PERF_METRICS true

#define _LIBCITADEL_STD_PREFIX "\033[0;34m[/]\033[0m "
#define _LIBCITADEL_ERR_PREFIX "\033[0;31m[/]\033[0m "
#define _LIBCITADEL_PERF_PREFIX "\033[0;33m[/] \033[1;37mPerformance:\033[0m "

#define _citadel_printf(prefix, format, args...)  \
    if (CITADEL_DEBUG) {                          \
        printf(prefix format, ## args);           \
    }

#define citadel_printf(format, args...) _citadel_printf(_LIBCITADEL_STD_PREFIX, format, ## args);
#define citadel_perror(format, args...) _citadel_printf(_LIBCITADEL_ERR_PREFIX, format, ## args);
#define citadel_perf(format, args...) _citadel_printf(_LIBCITADEL_PERF_PREFIX, format, ## args);
#endif

#ifdef __cplusplus
}
#endif