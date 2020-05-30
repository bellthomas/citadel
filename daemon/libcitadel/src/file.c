

#include "../include/citadel/file.h"
#include "../include/citadel/cache.h"
#include <sys/types.h>
#include <sys/xattr.h>

static bool cache_hit(const char *path, size_t length, citadel_operation_t op) {
	// Check cache.
	libcitadel_cache_item_t *head = cache_group_head(LIBCITADEL_CACHE_FILE_NAMES);
	
	while (head) {
		if (memcmp(path, head->data, length) == 0 && (head->op & op) != 0) {
			return true;
		}
		head = head->next;
	}
	return false;
}

static bool _citadel_file_claim(const char *path, size_t length) {
	if (length > _CITADEL_MAX_METADATA_SIZE || length < 2) return false;

	// Check the cache.
	if (cache_hit(path, length, CITADEL_OP_CLAIM)) {
		citadel_printf("(*) Claiming %s\n", path);
		return true;
	}

	citadel_printf("Claiming %s\n", path);
	struct citadel_op_extended_request payload;
	memcpy(payload.request.signature, challenge_signature, sizeof(challenge_signature));
	payload.request.operation = CITADEL_OP_CLAIM | CITADEL_OP_OPEN;
	memcpy(payload.request.signed_ptoken, get_signed_ptoken(), sizeof(payload.request.signed_ptoken));
    memcpy(payload.metadata, path, length);
	payload.translate = false;

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_extended_request));
	if (success) {
		citadel_printf("Registered file: %s\n", path);
		libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_FILE_NAMES);
		printf("%p\n", entry);
		entry->op = CITADEL_OP_CLAIM | CITADEL_OP_OPEN;
		entry->data = malloc(length);
		memcpy(entry->data, path, length);

	} else {
		citadel_perror("Failed to register file: %s\n", path);
	}
	return success;
}

bool citadel_file_claim(const char *path, size_t length) {
	size_t xattr_len = getxattr(path, _CITADEL_XATTR_IDENTIFIER, NULL, 0);
	return (xattr_len == sizeof(_CITADEL_XATTR_IDENTIFIER)) ? true : _citadel_file_claim(path, length);
}

bool citadel_file_claim_force(const char *path, size_t length) {
	size_t xattr_len = getxattr(path, _CITADEL_XATTR_IDENTIFIER, NULL, 0);
	if (xattr_len == sizeof(_CITADEL_XATTR_IDENTIFIER)) citadel_printf("Overriding identifier for %s\n", path);
	return _citadel_file_claim(path, length);
}


bool _citadel_file_open_fd(int fd, char *identifier, citadel_operation_t operation, bool add_cache) {
	struct citadel_op_request payload;
	memcpy(payload.signature, challenge_signature, sizeof(challenge_signature));
	payload.operation = operation;
	memcpy(payload.signed_ptoken, get_signed_ptoken(), sizeof(payload.signed_ptoken));
    memcpy(payload.subject, identifier, _CITADEL_IDENTIFIER_LENGTH);

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_request));
	if (success) {
		citadel_printf("(+) Allowed to reopen FD: %d\n", fd);

		if (add_cache) {
			libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_FD);
			entry->op = operation;
			entry->fd = fd;
			entry->data = malloc(_CITADEL_IDENTIFIER_LENGTH);
			entry->update = _citadel_file_open_fd;
			memcpy(entry->data, identifier, _CITADEL_IDENTIFIER_LENGTH);
		}
	} else {
		citadel_perror("(+) Can't reopen file: %d\n", fd);
	}
	return success;
}


bool citadel_file_open_ext(const char *path, size_t length, bool *from_cache) {
	if (length > _CITADEL_MAX_METADATA_SIZE || length < 2) return false;

	if (cache_hit(path, length, CITADEL_OP_OPEN)) {
		citadel_printf("(*) Allowed to open file: %s\n", path);
		if (from_cache) *from_cache = true;
		return true;
	}

	struct citadel_op_extended_request payload;
	memcpy(payload.request.signature, challenge_signature, sizeof(challenge_signature));
	payload.request.operation = CITADEL_OP_OPEN;
	memcpy(payload.request.signed_ptoken, get_signed_ptoken(), sizeof(payload.request.signed_ptoken));
    memcpy(payload.metadata, path, length);
	payload.translate = true;

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_extended_request));
	if (success) {
		citadel_printf("Allowed to open file: %s\n", path);
		libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_FILE_NAMES);
		entry->op = CITADEL_OP_OPEN;
		entry->data = malloc(length);
		memcpy(entry->data, path, length);
	} else {
		citadel_perror("Can't open file: %s\n", path);
	}
	return success;
}

bool citadel_file_open(const char *path, size_t length) {
	return citadel_file_open_ext(path, length, NULL);
}

void citadel_declare_fd(int fd, citadel_operation_t op) {
	citadel_printf("Declaring FD\n");
	bool tainted = false;
	char *identifier = get_fd_identifier(fd, &tainted);
	if (tainted && identifier) {
		libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_FD);
		entry->op = op;
		entry->fd = fd;
		entry->data = malloc(_CITADEL_IDENTIFIER_LENGTH);
		entry->update = _citadel_file_open_fd;
		memcpy(entry->data, identifier, _CITADEL_IDENTIFIER_LENGTH);
		free(identifier);
	}
}