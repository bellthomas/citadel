  
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

#include "../include/citadel/ipc.h"

// static nng_socket sock;
// static nng_aio *ap;
static int socket_fd = -1;
static int ipc_timeout = 100 * 1000;
static bool initialised_socket = false;
static char buffer[sizeof(struct citadel_op_extended_request)];

static bool init_socket(void) {

	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		citadel_perror("socket error\n");
		return false;
  	}

	// Set non-blocking.
	int flags = fcntl(socket_fd, F_GETFL, 0);
	if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK)) {
		citadel_perror("failed to make socket non blocking\n");
		return false;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, _CITADEL_IPC_FILE, sizeof(_CITADEL_IPC_FILE));
	
	if (connect(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		citadel_perror("connect error\n");
		return false;
	}


	// int rv;
	// if ((rv = nng_req0_open(&sock)) != 0) {
    //     citadel_perror("Failed to open local socket.\n");
    //     return false;
	// }

    // if ((rv = nng_dial(sock, _CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
    //     citadel_perror("Failed to connect to %s: %s\n", _CITADEL_IPC_ADDRESS, nng_strerror(rv));
    //     return false;
	// }

	// if ((rv = nng_aio_alloc(&ap, NULL, NULL)) != 0) {
	// 	citadel_perror("Failed to init nng_aio: %s\n", nng_strerror(rv));
    //     return false;
	// }

    // nng_aio_set_timeout(ap, NNG_DURATION_ZERO);
	// nng_setopt_ms(sock, NNG_OPT_RECONNMINT, 0);
	// nng_setopt_bool(sock, NNG_OPT_RAW, true);
	// nng_setopt_ms(sock, NNG_OPT_RECONNMAXT, 1);
	// nng_setopt_size(sock, NNG_OPT_RECVMAXSZ, 0);

    initialised_socket = true;
	return true;
}

/*
 *
 */
bool ipc_send(char *data, size_t len) {

    if (!initialised_socket) initialised_socket = init_socket();
    if (!initialised_socket) return false;

	int attempts = 0;
	int rv;
	size_t sent = 0;

#if _LIBCITADEL_PERF_METRICS
	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
#endif

	// Set message.

	while (attempts < ipc_timeout) {
		
		// Try to send.
		rv = write(socket_fd, data, len);
		sent += (rv > 0 ? rv : 0);
		if (sent < len || (rv == -1 && (errno == EWOULDBLOCK || errno == EAGAIN))) {
			usleep(1);
			attempts++;
			if(attempts >= ipc_timeout) {
				citadel_perror("Timed out. Failed to send.\n");
				return false;
			}
			break;
		}

		else if (sent == len) {
#if _LIBCITADEL_PERF_METRICS
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			citadel_perf("ipc_send, %lluμs\n", (long long unsigned int) diff / 1000);
#endif
			return true;
		}
		else {
			citadel_perror("Error, %s\n", strerror(errno));
			return false;
		}
	}
}



/*
 *
 */
bool ipc_recv(void) {

    if (!initialised_socket) initialised_socket = init_socket();
    if (!initialised_socket) return false;

	int attempts = 0;
	size_t received = 0;
	int rv;
	char *buf = (char*)buffer;

#if _LIBCITADEL_PERF_METRICS
	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
#endif

	// TODO check that sock is still ok. eg IS_FD
	// if (!sock) return false;
	while (attempts < ipc_timeout) {

		// nng_recv_aio(sock, ap);
		// nng_aio_wait(ap);
		// rv = nng_aio_result(ap);
		// if(rv == 0) *msg = nng_aio_get_msg(ap);	
		// else if (rv == NNG_ETIMEDOUT) rv = NNG_EAGAIN;

		rv += read(socket_fd, buffer, sizeof(buffer));
		received += (rv > 0 ? rv : 0);
		if (rv == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			usleep(20);
			attempts++;
			if(attempts >= ipc_timeout) {
				citadel_perror("Timed out. Nothing received.\n");
				return false;
			}
			break;
		}


		else if (received > 0) {
#if _LIBCITADEL_PERF_METRICS
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			citadel_perf("ipc_recv, %lluμs (attempts %d)\n", (long long unsigned int) diff / 1000, attempts);
#endif

			return true;
		}
		else {
			citadel_perror("Error, %s\n", strerror(errno));
			return false;
		}
	}
}



/*
 *
 */
bool ipc_transaction(unsigned char *request, size_t length) {

    if (!initialised_socket) initialised_socket = init_socket();
    if (!initialised_socket) return false;

	if (length != sizeof(struct citadel_op_request) && length != sizeof(struct citadel_op_extended_request)) {
		citadel_perror("Unknown payload length.\n");
		return false;
	}

    int rv;
	// size_t sz;
	// char *buf = NULL;
	// bool success = false;
	bool received, sent;
	uint64_t pid;

    struct citadel_op_reply *reply;
    struct citadel_op_extended_reply *extended_reply;

    sent = ipc_send(request, length);	
	if (sent) {
		usleep(10);
		received = ipc_recv();
		if (received) {
			// Get PID of sender.

			// TODO actually get
			pid = get_citadel_pid();
			
			if (pid == get_citadel_pid()) {
				if (length > sizeof(struct citadel_op_reply)){
					// Unpack extended reply;
					extended_reply = (struct citadel_op_extended_reply *)buffer;
					reply = &extended_reply->reply;
				}
				else {
					// Just a simple reply.
					reply = (struct citadel_op_reply *)buffer;
				}

				// Check response ptoken.
				if( memcmp(reply->ptoken, get_ptoken(), sizeof(reply->ptoken)) && 
					memcmp(reply->signature, challenge_signature, sizeof(challenge_signature)))
				{
					citadel_perror("Transaction: response ptoken/signature incorrect.\n");
					return false;
				}

				// Check result.
				bool res = false;
				switch (reply->result) {
				case CITADEL_OP_APPROVED:
					res = true;
					break;
				default:
					citadel_perror("Transaction failed: %s.\n", citadel_error(reply->result));
				}

				return res;
			} else {
				citadel_perror("Forged transaction from PID %lu (Citadel PID: %d).\n", pid, get_citadel_pid());
			}

		} else {
			citadel_perror("Transaction failed (receive timed out).\n");
		}
	} else {
		citadel_perror("Transaction failed (send timed out).\n");
	}

    return false;
}