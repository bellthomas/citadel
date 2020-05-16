
#ifndef TRM_LSM_COMMS_H_
#define TRM_LSM_COMMS_H_

#include "Enclave_t.h"

#include <stdio.h>
#include <sgx_trts.h>
#include "enclave.h"
#include "../crypto/crypto.h"
#include "../../_citadel_shared.h"

extern sgx_status_t handle_kernel_challenge(uint8_t* challenge_data, size_t challenge_length, uint8_t* response_data, size_t response_length, int32_t pid);
extern void generate_ticket(int num_records);
extern void generate_xattr_ticket(void);

#endif
