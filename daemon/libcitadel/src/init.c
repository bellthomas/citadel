

#include "../include/citadel/init.h"

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

static int ipc_declare_self(void) {
	nng_socket sock;
	int        rv;
	size_t     sz;
	char *     buf = NULL;


	char *ptoken = getenv(CITADEL_SIGNED_ENV_ATTR_NAME);
	char *ptoken_raw = _hex_identifier_to_bytes(ptoken);


	//_TRM_PROCESS_SIGNED_PTOKEN_LENGTH

    
    if ((rv = nng_req0_open(&sock)) != 0) {
		// fatal("nng_socket", rv);
        printf("died at a\n");
        return -1;
	}

    if ((rv = nng_dial(sock, CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
		// fatal("nng_dial", rv);
        printf("died at b: %s\n", nng_strerror(rv));
        return -1;
	}
    


	
    // printf("CLIENT: SENDING DATE REQUEST\n");
	int attempts = 0;
	int timeout = 1000; // milliseconds
	int timeout_us = timeout * 1000;
	bool sent = false;
	while (attempts < timeout_us && !sent) {
		rv = nng_send(sock, ptoken_raw, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH, NNG_FLAG_NONBLOCK);
		switch (rv) {
		case NNG_EAGAIN:
			usleep(1);
			attempts++;
			if(attempts >= timeout_us) {
				printf("Timed out. Failed to send.\n");
				nng_close(sock);
				return -1;
			}
			break;
		case 0:
			sent = true;
			// printf("Sent\n");
			break;
		default:
			printf("Error, %s\n", nng_strerror(rv));
			nng_close(sock);
			return -1;
		}
	}

	// usleep(10);
    // printf("SENT\n");
	// if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
	// 	// fatal("nng_recv", rv);
    //     printf("died at d\n");
    //     return;
	// }

    // This assumes that buf is ASCIIZ (zero terminated).
	// nng_free(buf, sz);
	// TODO fix ^
	free(ptoken_raw);
	nng_close(sock);
    // printf("AT END\n");
    return 0;
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

	char *hex_ptoken = to_hexstring(ptoken_payload->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
	printf("ptoken: %s\n", hex_ptoken);
	int set_env = setenv(CITADEL_ENV_ATTR_NAME, hex_ptoken, 1);
	free(hex_ptoken);

	char *hex_signed_ptoken = to_hexstring(ptoken_payload->signed_ptoken, _TRM_PROCESS_SIGNED_PTOKEN_LENGTH);
	set_env += setenv(CITADEL_SIGNED_ENV_ATTR_NAME, hex_signed_ptoken, 1);
	free(hex_signed_ptoken);

	printf("Citadel PID: %d\n", ptoken_payload->citadel_pid);

	return set_env;
}

static void init_rand(void) {
	pid_t pid = getpid();
	printf("PID: %d\n", pid);
    time_t seconds = time(NULL);
    unsigned int seed = seconds + CITADEL_KEY_PID_MULTIPLIER * pid;
    srand(seed);
}

int citadel_init(void) {
	printf("---\n");
	init_rand();
	int res_ptoken = get_ptoken();
	printf("---\n");
	int res = ipc_declare_self();
    return 0;
}
