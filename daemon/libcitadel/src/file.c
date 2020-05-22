

#include "../include/citadel/file.h"
#include <sys/types.h>
#include <sys/xattr.h>

static bool _citadel_file_create(char *path, size_t length) {
	if (length > _CITADEL_MAX_METADATA_SIZE || length < 2) return false;

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

bool citadel_file_create(char *path, size_t length) {
	size_t xattr_len = getxattr(path, _CITADEL_XATTR_IDENTIFIER, NULL, 0);
	return xattr_len ? true : _citadel_file_create(path, length);
}

bool citadel_file_recreate(char *path, size_t length) {
	size_t xattr_len = getxattr(path, _CITADEL_XATTR_IDENTIFIER, NULL, 0);
	if (xattr_len) citadel_printf("Overriding identifier for %s\n", path);
	return _citadel_file_create(path, length);
}


bool citadel_file_open(char *path, size_t length) {
	if (length > _CITADEL_MAX_METADATA_SIZE || length < 2) return false;

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