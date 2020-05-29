#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/xattr.h>

#include "../include/citadel/socket.h"


bool _citadel_socket(int fd, char *identifier, citadel_operation_t operation, bool add_cache) {
	struct citadel_op_request request;
	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	memcpy(request.subject, identifier, sizeof(request.subject));
	request.operation = operation;
	memcpy(request.signed_ptoken, get_signed_ptoken(), sizeof(request.signed_ptoken));

	bool success = ipc_transaction((unsigned char*)&request, sizeof(struct citadel_op_request));
	if (success) {
		citadel_printf("Access to socket granted.\n");

		// Cache request.
		if (add_cache) {
			citadel_printf("Add socket cache entry\n");
			libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_FD);
			entry->op = operation;
			entry->fd = fd;
			entry->data = malloc(_CITADEL_IDENTIFIER_LENGTH);
			entry->update = _citadel_socket;
			memcpy(entry->data, identifier, _CITADEL_IDENTIFIER_LENGTH);
		}

	} else {
		citadel_perror("Socket access rejected.\n");
	}

	return success;
}

bool citadel_socket(int socket_fd, struct sockaddr *address, bool *tainted) {
    // Decide whether socket if for internal or external use.
    citadel_operation_t operation;
    if (address->sa_family == AF_UNIX || address->sa_family == AF_LOCAL)
        operation = CITADEL_OP_SOCKET_INTERNAL;
    else
        operation = CITADEL_OP_SOCKET_EXTERNAL;

	citadel_printf("citadel_socket\n");
	// Check permission, requesting if not.
	if (citadel_validate_fd(socket_fd, NULL, &operation, tainted, _citadel_socket)) 
		return true;
	return false;
}



