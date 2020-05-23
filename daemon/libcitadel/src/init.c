

#include "../include/citadel/init.h"

static int32_t citadel_pid = 0;
static char *ptoken = NULL;
static char *signed_ptoken = NULL;

const char *get_ptoken(void) {
	return ptoken;
}

const char *get_signed_ptoken(void) {
	return signed_ptoken;
}

const int32_t get_citadel_pid(void) {
	return citadel_pid;
}

void* _hex_identifier_to_bytes(char* hexstring) {
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


static bool ipc_declare_self(void) {
	struct citadel_op_request request;
	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	request.operation = CITADEL_OP_REGISTER;
	memcpy(request.signed_ptoken, signed_ptoken, sizeof(request.signed_ptoken));
	bool registered = ipc_transaction((unsigned char*)&request, sizeof(struct citadel_op_request));

	if (registered) {
		citadel_printf("Registered with Citadel (PID %d).\n", citadel_pid);
	}
	else {
		citadel_perror("Failed to register with Citadel.\n");
	}
	
	return registered;
}


static bool fetch_kernel_ptoken(void) {
	// Read challenge.
	FILE *f_challenge;
	unsigned char buffer[_CITADEL_PTOKEN_PAYLOAD_SIZE];
    f_challenge = fopen(_CITADEL_PROCESS_GET_PTOKEN_PATH, "rb");
	if (!f_challenge) {
		citadel_perror("Failed to open %s\n", _CITADEL_PROCESS_GET_PTOKEN_PATH);
		return false;
	}
    size_t challenge_read = fread(buffer, sizeof(buffer), 1, f_challenge);
    fclose(f_challenge);

	if (challenge_read == 0) {
		citadel_perror("Failed to retrieve ptoken.\n");
		citadel_perror("Please check that the kernel supports Citadel and that the daemon is running.\n");
		return false;
	}

	citadel_ptoken_t *ptoken_payload = (citadel_ptoken_t *)buffer;
	if(memcmp(ptoken_payload->signature, challenge_signature, sizeof(challenge_signature))) {
		citadel_perror("Payload signature doesn't match\n");
		return false;
	}

	// Save results locally.
	ptoken = malloc(_CITADEL_PROCESS_PTOKEN_LENGTH);
	memcpy(ptoken, ptoken_payload->ptoken, _CITADEL_PROCESS_PTOKEN_LENGTH);
	signed_ptoken = malloc(_CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH);
	memcpy(signed_ptoken, ptoken_payload->signed_ptoken, _CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH);
	citadel_pid = ptoken_payload->citadel_pid;

#if CITADEL_DEBUG
	char *hex_ptoken = to_hexstring(ptoken_payload->ptoken, _CITADEL_PROCESS_PTOKEN_LENGTH);
	citadel_printf("ptoken: %s\n", hex_ptoken);
	// int set_env = setenv(_CITADEL_ENV_ATTR_NAME, hex_ptoken, 1);
	free(hex_ptoken);

	// char *hex_signed_ptoken = to_hexstring(ptoken_payload->signed_ptoken, _CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH);
	// set_env += setenv(_CITADEL_SIGNED_ENV_ATTR_NAME, hex_signed_ptoken, 1);
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
	if (fetch_kernel_ptoken()) {
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


bool citadel_pty(void) {
	struct citadel_op_request request;
	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	request.operation = CITADEL_OP_PTY_ACCESS;
	memcpy(request.signed_ptoken, signed_ptoken, sizeof(request.signed_ptoken));
	bool registered = ipc_transaction((unsigned char*)&request, sizeof(struct citadel_op_request));

	if (registered) {
		citadel_printf("PTY access granted.\n");
	}
	else {
		citadel_perror("PTY access refused.\n");
	}
	
	return registered;
}