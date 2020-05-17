

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

	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

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
				printf("Timed out. Failed to send.\n");
				return false;
			}
			break;
		case 0:
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			// printf("* ipc_send -- %llu microseconds\n", (long long unsigned int) diff / 1000);
			return true;
		default:
			printf("Error, %s\n", nng_strerror(rv));
			return false;
		}
	}
}

static bool ipc_recv(nng_msg **msg) {
	int attempts = 0;
	int rv;

	uint64_t diff;
	struct timespec start, end;
	clock_gettime(CLOCK_MONOTONIC, &start);

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
				printf("Timed out. Nothing received.\n");
				return false;
			}
			break;
		case 0:
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			// printf("* ipc_recv -- %llu microseconds (attempts %d)\n--\n", (long long unsigned int) diff / 1000, attempts);
			return true;
		default:
			printf("Error, %s\n", nng_strerror(rv));
			return false;
		}
	}
}

static bool ipc_declare_self(void) {
	int        rv;
	size_t     sz;
	char *     buf = NULL;

	// char *ptoken = getenv(CITADEL_SIGNED_ENV_ATTR_NAME);
	// char *ptoken_raw = ptoken; //_hex_identifier_to_bytes(ptoken);

	bool success = false;
	bool sent = ipc_send(signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);	
	if (sent) {
		nng_msg *msg;

		bool received = ipc_recv(&msg);
		bool success = received;

		if (success) {
			// Get PID of sender.
			nng_pipe p = nng_msg_get_pipe(msg);
			uint64_t pid;
			nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &pid);
			
			if (pid == citadel_pid) {
				if(memcmp(signed_ptoken, nng_msg_body(msg), _TRM_PROCESS_SIGNED_PTOKEN_LENGTH)) {
					printf("Wrong payload back.\n");
				}
				// printf("* Successful transaction with Citadel enclave.\n");
			} else {
				printf("! Forged transaction from PID %lu (Citadel PID: %d).\n", pid, citadel_pid);
				success = false;
			}

			nng_msg_free(msg);

		} else {
			printf("! Init call failed (receive timed out).\n");
		}
	} else {
		printf("! Init call failed (send timed out).\n");
	}

	// Free resources.
	// if (ptoken_raw) free(ptoken_raw);
	// nng_close(sock);
    return success;
}

static bool init_socket(void) {
	int rv;
	if ((rv = nng_req0_open(&sock)) != 0) {
        printf("! Failed to open local socket.\n");
        return false;
	}

    if ((rv = nng_dial(sock, CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
		// fatal("nng_dial", rv);
        printf("! Failed to connect to %s: %s\n", CITADEL_IPC_ADDRESS, nng_strerror(rv));
        return false;
	}

	if ((rv = nng_aio_alloc(&ap, NULL, NULL)) != 0) {
		printf("! Failed to init nng_aio: %s\n", nng_strerror(rv));
        return false;
	}
    nng_aio_set_timeout(ap, NNG_DURATION_ZERO);
    // nng_aio_set_timeout(ap, 0.5);

	// nng_setopt_int(sock, NNG_OPT_RECVBUF, 10000);
	nng_setopt_ms(sock, NNG_OPT_RECONNMINT, 0);
	nng_setopt_bool(sock, NNG_OPT_RAW, true);
	nng_setopt_ms(sock, NNG_OPT_RECONNMAXT, 1);
	nng_setopt_size(sock, NNG_OPT_RECVMAXSZ, 0);

	return true;
}

int get_ptoken(void) {
	// Read challenge.
	FILE *f_challenge;
	unsigned char buffer[_TRM_PTOKEN_PAYLOAD_SIZE];
    f_challenge = fopen(_TRM_PROCESS_GET_PTOKEN_PATH, "rb");
    size_t challenge_read = fread(buffer, sizeof(buffer), 1, f_challenge);
    fclose(f_challenge);

	struct trm_ptoken *ptoken_payload = (struct trm_ptoken *)buffer;
	if(memcmp(ptoken_payload->signature, challenge_signature, sizeof(challenge_signature))) {
		printf("Payload signature doesn't match\n");
		return -1;
	}

	ptoken = malloc(_TRM_PROCESS_PTOKEN_LENGTH);
	memcpy(ptoken, ptoken_payload->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
	signed_ptoken = malloc(_TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	memcpy(signed_ptoken, ptoken_payload->signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);

	// char *hex_ptoken = to_hexstring(ptoken_payload->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
	// printf("ptoken: %s\n", hex_ptoken);
	// int set_env = setenv(CITADEL_ENV_ATTR_NAME, hex_ptoken, 1);
	// free(hex_ptoken);

	// char *hex_signed_ptoken = to_hexstring(ptoken_payload->signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	// set_env += setenv(CITADEL_SIGNED_ENV_ATTR_NAME, hex_signed_ptoken, 1);
	// free(hex_signed_ptoken);

	printf("Citadel PID: %d\n", ptoken_payload->citadel_pid);
	citadel_pid = ptoken_payload->citadel_pid;

	return 0;
}

static void init_rand(void) {
	pid_t pid = getpid();
	printf("PID: %d\n", pid);
    time_t seconds = time(NULL);
    unsigned int seed = seconds + CITADEL_KEY_PID_MULTIPLIER * pid;
    srand(seed);
}

int citadel_init(void) {
	// printf("---\n");
	init_rand();
	int res_ptoken = get_ptoken();
	init_socket();
	// printf("---\n");

	uint64_t diff;
	struct timespec start, end;
	long long int total_duration = 0;
	long int num_runs = 0;
	int res;

	for (size_t i = 0; i < 10; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);	/* mark start time */
		res = ipc_declare_self();
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		total_duration += diff;
		num_runs++;
		usleep((rand() % 50000));
		// printf("* %llu microseconds\n", (long long unsigned int) diff / 1000);
	}

	printf("Average duration = %llu microseconds\n", (long long unsigned int) ((total_duration / num_runs)/1000));
    return 0;
}
