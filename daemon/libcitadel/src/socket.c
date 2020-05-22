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
	}
	free(id);
}
