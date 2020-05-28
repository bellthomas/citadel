#ifndef _LIBCITADEL_SOCKET_H
#define _LIBCITADEL_SOCKET_H

#include <sys/types.h>
#include <sys/socket.h>

#include "citadel.h"

extern bool citadel_socket(int socket_fd, struct sockaddr *address, bool *tainted);
extern bool citadel_validate_socket_fd(int sockfd, char *identifier, citadel_operation_t *op, bool *tainted);

#endif