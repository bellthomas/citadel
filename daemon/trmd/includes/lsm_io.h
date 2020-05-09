

#ifndef _U_ENCLAVE_TRM_LSM_IO_H
#define _U_ENCLAVE_TRM_LSM_IO_H

#include <stdio.h>
#include <iostream>
#include <sys/xattr.h>
#include <sys/types.h>
#include <errno.h>

#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"

#include "app.h"

extern int lsm_register();
extern int trigger_process_updates();
extern int install_xattr(const char *path, char *value, size_t size);

#endif  /* _U_ENCLAVE_TRM_LSM_IO_H */