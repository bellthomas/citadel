#include <sys/types.h>
#include <sys/socket.h> 
#include <sys/xattr.h>

#include "../include/citadel/socket.h"

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

static bool _citadel_socket(int fd, char *identifier, citadel_operation_t operation, bool add_cache) {
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
			libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_SOCKET_FD);
			entry->op = operation;
			entry->fd = fd;
			entry->data = malloc(_CITADEL_IDENTIFIER_LENGTH);
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


	// Check permission, requesting if not.
	if (citadel_validate_socket_fd(socket_fd, NULL, &operation, tainted)) 
		return true;
	return false;

	// bool success = _citadel_socket(identifier, operation);

    // return success;
}


static char *get_fd_identifier(int fd, bool *tainted) {
	void *id, *id_raw;

	if (tainted) *tainted = true;
	id = malloc(_CITADEL_ENCODED_IDENTIFIER_LENGTH);
	ssize_t read = fgetxattr(fd, _CITADEL_XATTR_IDENTIFIER, id, _CITADEL_ENCODED_IDENTIFIER_LENGTH);
	
	if (read == _CITADEL_ENCODED_IDENTIFIER_LENGTH) {
		citadel_printf("Socket identifier: %s\n", (char*)id);
	} else if (read == -1) {
		citadel_printf("Socket not tainted.\n");
		if (tainted) *tainted = false;
		free(id);
		return NULL;
	}
	else {
		citadel_printf("Fail. Got %ld bytes for identifier\n", read);
		free(id);
		return NULL;
	}

	id_raw = (char*)_hex_identifier_to_bytes(id);
	free(id);
	return id_raw;
}


bool citadel_validate_socket_fd(int sockfd, char *identifier, citadel_operation_t *op, bool *tainted) {
	bool ret = false;

	// If not supplied with the identifier get it.
	bool _taint = true;
	if (!identifier)
		identifier = get_fd_identifier(sockfd, &_taint);
	if (tainted) *tainted = _taint;
	if (!_taint) return true;


	// Check cache.
	libcitadel_cache_item_t *head = cache_group_head(LIBCITADEL_CACHE_SOCKET_FD);
	libcitadel_cache_item_t *prev = NULL, *tmp = NULL;
	while (head) {
		if (head->fd == sockfd) {
			if (!op || *op == head->op) {
				if (memcmp(identifier, head->data, _CITADEL_IDENTIFIER_LENGTH) == 0) {
					// This is the correct item.
					ret = true;
					citadel_printf("Socket entry in cache\n");
					if (entry_in_date(head)) goto bail_validate_socket;
					citadel_printf("... out of date.\n");
					// Out of date, refresh.
					ret = _citadel_socket(sockfd, identifier, head->op, false);
					citadel_printf("success: %d\n", ret);
					if (!ret) goto bail_validate_socket;

					citadel_printf("updating cache\n");
					update_cache_timestamp(head);
					if (head->next) move_cache_item_to_end(head, prev, LIBCITADEL_CACHE_SOCKET_FD);

					goto bail_validate_socket;
				}
			}
		}
		prev = head;
		head = head->next;
	}
	citadel_printf("Socket FD not found in cache\n");

	if (op)
		ret = _citadel_socket(sockfd, identifier, *op, true);

bail_validate_socket:
	if (identifier) free(identifier);
	return ret;
}
