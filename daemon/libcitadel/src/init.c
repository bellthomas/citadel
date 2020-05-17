

#include "../include/citadel/init.h"

#include <time.h>

static int ipc_timeout = 1 * 1000 * 1000; // microseconds
static int32_t citadel_pid = 0;
static nng_socket sock;
static nng_aio *ap;
static char *ptoken = NULL;
static char *signed_ptoken = NULL;

static void* _hex_identifier_to_bytes(char* hexstring) {
	size_t i, j;
	size_t len = strlen(hexstring);
	size_t final_len = len / 2;
	unsigned char* identifier; 

    if(len % 2 != 0) return NULL;

	identifier = (unsigned char*) malloc(final_len);
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        identifier[j] = (hexstring[i] % 32 + 9) % 25 * 16 + (hexstring[i+1] % 32 + 9) % 25;
	}
	return identifier;
}


static bool ipc_send(char *data, size_t len) {
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

static bool ipc_recv(nng_msg **msg) {
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

static bool ipc_declare_self(void) {
	int rv;
	size_t sz;
	char *buf = NULL;
	bool success = false;
	bool received, sent;
	uint64_t pid;
	nng_msg *msg;

	struct citadel_op_request request;
	struct citadel_op_reply *reply;

	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	request.operation = CITADEL_OP_REGISTER;
	memcpy(request.signed_ptoken, signed_ptoken, sizeof(request.signed_ptoken));

	sent = ipc_send((char*)&request, sizeof(struct citadel_op_request));	
	if (sent) {
		received = ipc_recv(&msg);
		if (received) {
			// Get PID of sender.
			nng_pipe p = nng_msg_get_pipe(msg);
			nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &pid);
			
			if (pid == citadel_pid) {
				reply = (struct citadel_op_reply *)nng_msg_body(msg);

				// Check response ptoken.
				if( memcmp(reply->ptoken, ptoken, sizeof(reply->ptoken)) && 
					memcmp(reply->signature, challenge_signature, sizeof(challenge_signature)))
				{
					citadel_perror("Registration: response ptoken/signature incorrect.\n");
					nng_msg_free(msg);
					return false;
				}

				// Check result.
				bool res = false;
				switch (reply->result) {
				case CITADEL_OP_APPROVED:
					citadel_printf("Registered with Citadel (PID %d).\n", citadel_pid);
					res = true;
					break;
				default:
					citadel_perror("Registration failed: %s.\n", citadel_error(reply->result));
				}

				nng_msg_free(msg);
				return res;
			} else {
				citadel_perror("Forged transaction from PID %lu (Citadel PID: %d).\n", pid, citadel_pid);
			}

			nng_msg_free(msg);

		} else {
			citadel_perror("Init call failed (receive timed out).\n");
		}
	} else {
		citadel_perror("Init call failed (send timed out).\n");
	}

    return false;
}

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

	return true;
}

static bool get_ptoken(void) {
	// Read challenge.
	FILE *f_challenge;
	unsigned char buffer[_TRM_PTOKEN_PAYLOAD_SIZE];
    f_challenge = fopen(_TRM_PROCESS_GET_PTOKEN_PATH, "rb");
	if (!f_challenge) {
		citadel_perror("Failed to open %s\n", _TRM_PROCESS_GET_PTOKEN_PATH);
		return false;
	}
    size_t challenge_read = fread(buffer, sizeof(buffer), 1, f_challenge);
    fclose(f_challenge);

	struct trm_ptoken *ptoken_payload = (struct trm_ptoken *)buffer;
	if(memcmp(ptoken_payload->signature, challenge_signature, sizeof(challenge_signature))) {
		citadel_perror("Payload signature doesn't match\n");
		return false;
	}

	// Save results locally.
	ptoken = malloc(_TRM_PROCESS_PTOKEN_LENGTH);
	memcpy(ptoken, ptoken_payload->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
	signed_ptoken = malloc(_TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	memcpy(signed_ptoken, ptoken_payload->signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	citadel_pid = ptoken_payload->citadel_pid;

#if CITADEL_DEBUG
	char *hex_ptoken = to_hexstring(ptoken_payload->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
	citadel_printf("ptoken: %s\n", hex_ptoken);
	// int set_env = setenv(CITADEL_ENV_ATTR_NAME, hex_ptoken, 1);
	free(hex_ptoken);

	// char *hex_signed_ptoken = to_hexstring(ptoken_payload->signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	// set_env += setenv(CITADEL_SIGNED_ENV_ATTR_NAME, hex_signed_ptoken, 1);
	// free(hex_signed_ptoken);
#endif

	return true;
}

static void init_rand(void) {
	pid_t pid = getpid();
	citadel_printf("PID: %d\n", pid);
    time_t seconds = time(NULL);
    unsigned int seed = seconds + CITADEL_KEY_PID_MULTIPLIER * pid;
    srand(seed);
}


bool citadel_init(void) {
	init_rand();
	if (get_ptoken() && init_socket()) {
		return ipc_declare_self();
	}

	return false;

	// uint64_t diff;
	// struct timespec start, end;
	// long long int total_duration = 0;
	// long int num_runs = 0;
	// int res;

	// for (size_t i = 0; i < 10; i++) {
	// 	clock_gettime(CLOCK_MONOTONIC, &start);	/* mark start time */
	// 	res = ipc_declare_self();
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	total_duration += diff;
	// 	num_runs++;
	// 	usleep((rand() % 50000));
	// 	printf("* %llu microseconds\n", (long long unsigned int) diff / 1000);
	// }

	// citadel_printf("Average duration = %llu microseconds\n", (long long unsigned int) ((total_duration / num_runs)/1000));
}
