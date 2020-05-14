

#include "../include/citadel/init.h"

#include <nng/nng.h>
#include <nng/protocol/reqrep0/rep.h>
#include <nng/protocol/reqrep0/req.h>
#include <nng/transport/ipc/ipc.h>

static char *generate_random_key(void) {
    pid_t pid = getpid();
    time_t seconds = time(NULL);
    printf("PID: %d\n", pid);
    unsigned int seed = seconds + CITADEL_KEY_PID_MULTIPLIER * pid;

    srand(seed);
    char *key = (char*) malloc(CITADEL_ENV_KEY_SIZE + 1);
    for (size_t i = 0 ; i < CITADEL_ENV_KEY_SIZE; i++) key[i] = (rand()%(90-65))+65;
    key[CITADEL_ENV_KEY_SIZE] = '\0';
    return key;
}


#define DATECMD 1

#define PUT64(ptr, u)                                        \
	do {                                                 \
		(ptr)[0] = (uint8_t)(((uint64_t)(u)) >> 56); \
		(ptr)[1] = (uint8_t)(((uint64_t)(u)) >> 48); \
		(ptr)[2] = (uint8_t)(((uint64_t)(u)) >> 40); \
		(ptr)[3] = (uint8_t)(((uint64_t)(u)) >> 32); \
		(ptr)[4] = (uint8_t)(((uint64_t)(u)) >> 24); \
		(ptr)[5] = (uint8_t)(((uint64_t)(u)) >> 16); \
		(ptr)[6] = (uint8_t)(((uint64_t)(u)) >> 8);  \
		(ptr)[7] = (uint8_t)((uint64_t)(u));         \
	} while (0)

#define GET64(ptr, v)                                 \
	v = (((uint64_t)((uint8_t)(ptr)[0])) << 56) + \
	    (((uint64_t)((uint8_t)(ptr)[1])) << 48) + \
	    (((uint64_t)((uint8_t)(ptr)[2])) << 40) + \
	    (((uint64_t)((uint8_t)(ptr)[3])) << 32) + \
	    (((uint64_t)((uint8_t)(ptr)[4])) << 24) + \
	    (((uint64_t)((uint8_t)(ptr)[5])) << 16) + \
	    (((uint64_t)((uint8_t)(ptr)[6])) << 8) +  \
	    (((uint64_t)(uint8_t)(ptr)[7]))

static void ipc_declare_self(void) {
	nng_socket sock;
	int        rv;
	size_t     sz;
	char *     buf = NULL;
	uint8_t    cmd[sizeof(uint64_t)];

	PUT64(cmd, DATECMD);
    
    if ((rv = nng_req0_open(&sock)) != 0) {
		// fatal("nng_socket", rv);
        printf("died at a\n");
        return;
	}

    if ((rv = nng_dial(sock, CITADEL_IPC_URI, NULL, 0)) != 0) {
		// fatal("nng_dial", rv);
        printf("died at b\n");
        return;
	}
    
    // memset(cmd, 5, sizeof(uint64_t));
    

    printf("CLIENT: SENDING DATE REQUEST\n");
    if ((rv = nng_send(sock, cmd, sizeof(cmd), 0)) != 0) {
		// fatal("nng_send", rv);
        printf("died at c\n");
        return;
	}
    printf("SENT\n");
	if ((rv = nng_recv(sock, &buf, &sz, NNG_FLAG_ALLOC)) != 0) {
		// fatal("nng_recv", rv);
        printf("died at d\n");
        return;
	}

    // This assumes that buf is ASCIIZ (zero terminated).
	nng_free(buf, sz);
	nng_close(sock);
    printf("AT END\n");
    return;
}

int citadel_init(void) {
    char *key = generate_random_key();
    int set_env = setenv(CITADEL_ENV_ATTR_NAME, key, 1);
    printf("%s, %d\n", key, set_env);
    ipc_declare_self();
    return 0;
}
