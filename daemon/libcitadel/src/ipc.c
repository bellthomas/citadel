
#include "../include/citadel/ipc.h"

static nng_socket sock;
static nng_aio *ap;
static int ipc_timeout = 1 * 1000 * 1000; // microseconds
static bool initialised_socket = false;

static bool init_socket(void) {
	int rv;
	if ((rv = nng_req0_open(&sock)) != 0) {
        citadel_perror("Failed to open local socket.\n");
        return false;
	}

    if ((rv = nng_dial(sock, CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
        citadel_perror("Failed to connect to %s: %s\n", CITADEL_IPC_ADDRESS, nng_strerror(rv));
        return false;
	}

	if ((rv = nng_aio_alloc(&ap, NULL, NULL)) != 0) {
		citadel_perror("Failed to init nng_aio: %s\n", nng_strerror(rv));
        return false;
	}

    nng_aio_set_timeout(ap, NNG_DURATION_ZERO);
	nng_setopt_ms(sock, NNG_OPT_RECONNMINT, 0);
	nng_setopt_bool(sock, NNG_OPT_RAW, true);
	nng_setopt_ms(sock, NNG_OPT_RECONNMAXT, 1);
	nng_setopt_size(sock, NNG_OPT_RECVMAXSZ, 0);

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
	nng_msg *msg;

#if _LIBCITADEL_PERF_METRICS
	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
#endif

	if ((rv = nng_msg_alloc(&msg, len)) != 0) {
		return false;
	}
	memcpy(nng_msg_body(msg), data, len);


	// TODO check that sock is still ok.
	// if (!sock) return false;
	while (attempts < ipc_timeout) {
		nng_aio_set_msg(ap, msg);
		nng_send_aio(sock, ap);
		nng_aio_wait(ap);
		rv = nng_aio_result(ap);

		

		// rv = nng_send(*sock, data, len, NNG_FLAG_NONBLOCK);
		switch (rv) {
		case NNG_EAGAIN:
			usleep(1);
			attempts++;
			if(attempts >= ipc_timeout) {
				citadel_perror("Timed out. Failed to send.\n");
				return false;
			}
			break;
		case 0:

#if _LIBCITADEL_PERF_METRICS
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			citadel_perf("ipc_send, %lluμs\n", (long long unsigned int) diff / 1000);
#endif
			return true;
		default:
			citadel_perror("Error, %s\n", nng_strerror(rv));
			return false;
		}
	}
}



/*
 *
 */
bool ipc_recv(nng_msg **msg) {

    if (!initialised_socket) initialised_socket = init_socket();
    if (!initialised_socket) return false;

	int attempts = 0;
	int rv;

#if _LIBCITADEL_PERF_METRICS
	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);
#endif

	// TODO check that sock is still ok.
	// if (!sock) return false;
	while (attempts < ipc_timeout) {
		nng_recv_aio(sock, ap);
		nng_aio_wait(ap);
		rv = nng_aio_result(ap);
		if(rv == 0) *msg = nng_aio_get_msg(ap);	
		else if (rv == NNG_ETIMEDOUT) rv = NNG_EAGAIN;

		switch (rv) {
		case NNG_EAGAIN:
			usleep(1);
			attempts++;
			if(attempts >= ipc_timeout) {
				citadel_perror("Timed out. Nothing received.\n");
				return false;
			}
			break;
		case 0:

#if _LIBCITADEL_PERF_METRICS
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			citadel_perf("ipc_recv, %lluμs (attempts %d)\n", (long long unsigned int) diff / 1000, attempts);
#endif

			return true;
		default:
			citadel_perror("Error, %s\n", nng_strerror(rv));
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
    nng_msg *msg;

    struct citadel_op_reply *reply;
    struct citadel_op_extended_reply *extended_reply;

    sent = ipc_send(request, length);	
	if (sent) {
		received = ipc_recv(&msg);
		if (received) {
			// Get PID of sender.
			nng_pipe p = nng_msg_get_pipe(msg);
			nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &pid);
			
			if (pid == get_citadel_pid()) {
				if (length > sizeof(struct citadel_op_reply)){
					// Unpack extended reply;
					extended_reply = (struct citadel_op_extended_reply *)nng_msg_body(msg);
					reply = &extended_reply->reply;
				}
				else {
					// Just a simple reply.
					reply = (struct citadel_op_reply *)nng_msg_body(msg);
				}

				// Check response ptoken.
				if( memcmp(reply->ptoken, get_ptoken(), sizeof(reply->ptoken)) && 
					memcmp(reply->signature, challenge_signature, sizeof(challenge_signature)))
				{
					citadel_perror("Transaction: response ptoken/signature incorrect.\n");
					nng_msg_free(msg);
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

				nng_msg_free(msg);
				return res;
			} else {
				citadel_perror("Forged transaction from PID %lu (Citadel PID: %d).\n", pid, get_citadel_pid());
			}

			nng_msg_free(msg);

		} else {
			citadel_perror("Transaction failed (receive timed out).\n");
		}
	} else {
		citadel_perror("Transaction failed (send timed out).\n");
	}

    return false;
}