

#ifndef _U_ENCLAVE_TRM_APP_H
#define _U_ENCLAVE_TRM_APP_H

#include <stdio.h>
#include <iostream>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#include "../../_citadel_shared.h"
#include "lsm_io.h"
#include "socket.h"
#include "identifier_cache.h"

#define SUCCESS(x) (x == 0)

extern sgx_enclave_id_t get_enclave_id();

#endif  /* _U_ENCLAVE_TRM_APP_H */