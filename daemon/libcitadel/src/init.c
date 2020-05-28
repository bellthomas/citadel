

#include "../include/citadel/init.h"

static int32_t citadel_pid = 0;
static int32_t own_pid = 0;
static int32_t parent_pid = 0;

static char identifier[_CITADEL_IDENTIFIER_LENGTH], parent_identifier[_CITADEL_IDENTIFIER_LENGTH];
static char *ptoken = NULL;
static char *signed_ptoken = NULL;

/* Getters */
const char *get_ptoken(void) { return ptoken; }
const char *get_signed_ptoken(void) { return signed_ptoken; }
const int32_t get_citadel_pid(void) { return citadel_pid; }
const int32_t get_own_pid(void) { return citadel_pid; }
const int32_t get_parent_pid(void) { return citadel_pid; }
const char *get_identifier(void) { return (const char *)identifier; }
const char *get_parent_identifier(void) { return (const char *)parent_identifier; }

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
	memcpy(identifier, ptoken_payload->process_identifier, _CITADEL_IDENTIFIER_LENGTH);

#if CITADEL_DEBUG
	char *hex_ptoken = to_hexstring(ptoken_payload->process_identifier, _CITADEL_IDENTIFIER_LENGTH);
	citadel_printf("Process ID: %s\n", hex_ptoken);
	free(hex_ptoken);

	if (*((uint64_t*)parent_identifier) > 0) {
		char *hex_ptoken2 = to_hexstring(parent_identifier, _CITADEL_IDENTIFIER_LENGTH);
		citadel_printf("Parent ID:  %s\n", hex_ptoken2);
		free(hex_ptoken2);
	}
#endif

	return true;
}

static bool init_pid(void) {
	pid_t pid = getpid();
	pid_t ppid = getppid();

	// Check if already registered.
	if (pid == own_pid) return false;

	// Check for suspect fork.
	if (own_pid > 0 && own_pid != pid && own_pid != ppid) {
		citadel_perror("Suspect PID... (current: %d, parent: %d, actual: %d)\n", pid, ppid, own_pid);
	}
	else if (own_pid == ppid) {
		memcpy(parent_identifier, identifier, _CITADEL_IDENTIFIER_LENGTH);
	}

	citadel_printf("PID: %d\n", pid);
	own_pid = pid;
	parent_pid = ppid;
	return true;
}

static void init_rand(void) {
	
    time_t seconds = time(NULL);
    unsigned int seed = seconds + CITADEL_KEY_PID_MULTIPLIER * own_pid;
    srand(seed);
}


bool citadel_init(void) {
	if (!init_pid()) return true;
	init_rand();
	init_cache();
	if (fetch_kernel_ptoken()) {
		return ipc_declare_self();
	}

	return false;
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

bool citadel_parent_pipe(void) {
	if (parent_pid == 0) {
		citadel_perror("Parent process identifier unknown.\n");
		return false;
	}

	struct citadel_op_request request;
	memcpy(request.signature, challenge_signature, sizeof(challenge_signature));
	request.operation = CITADEL_OP_OPEN;
	memcpy(request.subject, parent_identifier, _CITADEL_IDENTIFIER_LENGTH);
	memcpy(request.signed_ptoken, signed_ptoken, sizeof(request.signed_ptoken));
	bool registered = ipc_transaction((unsigned char*)&request, sizeof(struct citadel_op_request));
	if (registered) {
		citadel_printf("Parent pipe access granted.\n");
	}
	else {
		citadel_perror("Parent pipe access refused.\n");
	}
	
	return registered;
}