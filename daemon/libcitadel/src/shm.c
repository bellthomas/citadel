
#include "../include/citadel/shm.h"

bool citadel_shm_access(key_t key) {
    struct citadel_op_request payload;
	memcpy(payload.signature, challenge_signature, sizeof(challenge_signature));
	payload.operation = CITADEL_OP_SHM;
	memcpy(payload.signed_ptoken, get_signed_ptoken(), sizeof(payload.signed_ptoken));
    memcpy(payload.subject, &key, sizeof(key_t));
    memset(payload.subject + sizeof(key_t), 0, sizeof(payload.subject) - sizeof(key_t));

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_request));
	if (success) {
		citadel_printf("Enabled SHM access: %u\n", key);
	} else {
		citadel_perror("Rejected SHM access: %u\n", key);
	}
	return success;}