

#include "../include/citadel/file.h"

bool citadel_file_create(char *path, size_t length) {
    if (length > CITADEL_MAX_METADATA_SIZE || length < 2) return false;

	struct citadel_op_extended_request payload;
	memcpy(payload.request.signature, challenge_signature, sizeof(challenge_signature));
	payload.request.operation = CITADEL_OP_FILE_CREATE;
	memcpy(payload.request.signed_ptoken, get_signed_ptoken(), sizeof(payload.request.signed_ptoken));
    memcpy(payload.metadata, path, length);

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_extended_request));
	if (success) {
		citadel_printf("Registered file: %s\n", path);
	} else {
		citadel_perror("Failed to register file: %s\n", path);
	}
	return success;
}


bool citadel_file_open(char *path, size_t length) {
	if (length > CITADEL_MAX_METADATA_SIZE || length < 2) return false;

	struct citadel_op_extended_request payload;
	memcpy(payload.request.signature, challenge_signature, sizeof(challenge_signature));
	payload.request.operation = CITADEL_OP_FILE_OPEN;
	memcpy(payload.request.signed_ptoken, get_signed_ptoken(), sizeof(payload.request.signed_ptoken));
    memcpy(payload.metadata, path, length);

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_extended_request));
	if (success) {
		citadel_printf("Allowed to open file: %s\n", path);
	} else {
		citadel_perror("Can't open file: %s\n", path);
	}
	return success;
}