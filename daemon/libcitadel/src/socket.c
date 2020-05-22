#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/xattr.h>

#include "../include/citadel/socket.h"

bool citadel_socket(int socket_fd, struct sockaddr *address) {
    // Decide whether socket if for internal or external use.
    citadel_operation_t operation;
    if (address->sa_family == AF_UNIX || address->sa_family == AF_LOCAL)
        operation = CITADEL_OP_SOCKET_INTERNAL;
    else
        operation = CITADEL_OP_SOCKET_EXTERNAL;

    // Check if socket is tainted.
    citadel_printf("Socket FD: %d\n", socket_fd);
	void *id = malloc(_CITADEL_ENCODED_IDENTIFIER_LENGTH);
	ssize_t read = fgetxattr(socket_fd, _CITADEL_XATTR_IDENTIFIER, id, _CITADEL_ENCODED_IDENTIFIER_LENGTH);
	
	if (read == _CITADEL_ENCODED_IDENTIFIER_LENGTH) {
		citadel_printf("Socket identifier: %s\n", (char*)id);
	} else {
		citadel_printf("Fail. Got %ld bytes for identifier\n", read);
        free(id);

        return false;
	}

    char *identifier = (char*)_hex_identifier_to_bytes(id);

    struct citadel_op_request request;
	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	memcpy(request.subject, identifier, sizeof(request.subject));
	request.operation = operation;
	memcpy(request.signed_ptoken, get_signed_ptoken(), sizeof(request.signed_ptoken));

	bool success = ipc_transaction((unsigned char*)&request, sizeof(struct citadel_op_request));
	if (success) {
		citadel_printf("Access to socket granted.\n");
	} else {
		citadel_perror("Socket access rejected.\n");
	}

    free(identifier);
	free(id);
    return success;
}
