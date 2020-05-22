
#ifndef TRM_USER_COMMS_H_
#define TRM_USER_COMMS_H_

#include "Enclave_t.h"

#include <stdio.h>
#include <sgx_trts.h>
#include "enclave.h"
#include "../crypto/crypto.h"
#include "../../_citadel_shared.h"

extern uint8_t handle_request(uint8_t* data, size_t length, int32_t pid, uint8_t* ptoken, size_t ptoken_length);
extern void set_ptoken_aes_key(unsigned char* key);
extern void protect_socket(void);

#endif
