#include "includes/socket.h"

#include <iostream>
#include <chrono>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>

static pthread_t thid;
static int socket_fd;
static bool running = true;
static long long int num_requests = 0;


char* to_hexstring(unsigned char *buf, unsigned int len) {
    char   *out;
	size_t  i;

    if (buf == NULL || len == 0) return NULL;

    out = (char*)malloc(2*len+1);
    for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[buf[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[buf[i] & 0x0F];
	}
    out[len*2] = '\0';
    return out;
}

void handle_client_socket(int client_fd) {
	printf("FD: %d\n", client_fd);
}

void run_server(void) {
    int rv;
	char *h;
	uint8_t ecall_ret;
	uint8_t ptoken[_CITADEL_PROCESS_PTOKEN_LENGTH];
	bool cache_stage, valid_size;
	struct citadel_op_reply *reply;
	uint64_t pid = 0;
	void *message;
	size_t message_len;

	int client_fd;
	struct sockaddr_un client;
	int c;

	while (running) {


		// nng_recv_aio(sock, ap);
		// nng_aio_wait(ap);
		// rv = nng_aio_result(ap);
		// if(rv == 0) msg = nng_aio_get_msg(ap);	
		// else if (rv == NNG_ETIMEDOUT) rv = NNG_EAGAIN;
	
		// rv = nng_recvmsg(sock, &msg, NNG_FLAG_NONBLOCK);
		// rv = nng_recv(sock, &buf, &sz, NNG_FLAG_NONBLOCK | NNG_FLAG_ALLOC);
		client_fd = accept(socket_fd, (struct sockaddr *)&client, (socklen_t*)&c);
		if (client_fd > 0) {
			// Got a connection.
			handle_client_socket(client_fd);
		}

		else if (client_fd == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			continue;
		}
		else {
			printf("Error: %s\n", strerror(errno));
		}

		// switch (rv) {
		// case NNG_EAGAIN:
		// 	// Nothing this time.
		// 	break;
		// case 0:
		// 	// if (!started) {
		// 	// 	started = true;
		// 	// 	start = std::chrono::high_resolution_clock::now();
		// 	// }

		// 	p = nng_msg_get_pipe(msg);
		// 	nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &pid);
		// 	printf("Received message: %lu bytes from PID %ld\n", nng_msg_len(msg), pid);

		// 	message = nng_msg_body(msg);
		// 	message_len = nng_msg_len(msg);

		// 	// Check length;
		// 	valid_size = (message_len == sizeof(struct citadel_op_request)) || (message_len == sizeof(struct citadel_op_extended_request));

		// 	// Process request.
		// 	ecall_ret = valid_size ? CITADEL_OP_ERROR : CITADEL_OP_INVALID; // Default.
		// 	cache_stage = valid_size ? cache_passthrough(message, message_len) : false;
		// 	if (cache_stage) {
		// 		handle_request(get_enclave_id(), &ecall_ret, (uint8_t*)message, message_len, (int32_t)pid, ptoken, sizeof(ptoken));
		// 	}
		// 	// printf("Result: %s\n", citadel_error(ecall_ret));

		// 	// Copy result into buffer to return to caller.
		// 	if (message_len == sizeof(struct citadel_op_extended_reply)) {
		// 		struct citadel_op_extended_reply *extended_reply = (struct citadel_op_extended_reply *)message;
		// 		reply = &extended_reply->reply;
		// 	} else {
		// 		reply = (struct citadel_op_reply *)message;
		// 	}
		// 	memcpy(reply->ptoken, ptoken, _CITADEL_PROCESS_PTOKEN_LENGTH);
		// 	reply->result = ecall_ret;

		// 	// rv = nng_sendmsg(sock, msg, NNG_FLAG_ALLOC);
		// 	nng_aio_set_msg(ap2, msg);
		// 	nng_send_aio(sock, ap2);
		// 	nng_aio_wait(ap2);
		// 	rv = nng_aio_result(ap2);
		// 	if (rv != 0) {
		// 		printf("nng_send failed\n");
		// 		nng_msg_free(msg);
		// 	}

		// 	num_requests++;
		// 	break;

		// default:
		// 	printf("Socket error: %s\n", nng_strerror(rv));
		// 	return;
		// }
		usleep(10);
	}

	// end = std::chrono::high_resolution_clock::now();
	// std::chrono::duration<double> diff = end-start;
	// std::cout << num_requests << " requests in " << std::chrono::duration_cast<std::chrono::microseconds>(diff).count() << " us\n";
	// nng_close(sock);
}



void *socket_thread(void *arg) {
    char *ret;

	// ECALL to protect socket, then start it.
    run_server();

    strcpy(ret, "This is a test");
    pthread_exit(ret);
}



// External.

int initialise_socket(void) {
	// int rv;
	// if ((rv = nng_rep0_open(&sock)) != 0) {
	// 	printf("nng_rep0_open fail\n");
    //     return -1;
	// }
	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error\n");
		return false;
  	}

	// Set non-blocking.
	int flags = fcntl(socket_fd, F_GETFL, 0);
	if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK)) {
		perror("failed to make socket non blocking\n");
		return false;
	}

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, _CITADEL_IPC_FILE, sizeof(_CITADEL_IPC_FILE));
	
	// Change permissions so anyone can read/write, then listen.
	umask(0);
	if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error\n");
		return false;
	}
	umask(22); // Default.

	// Mark as passive socket.
	listen(socket_fd, 5);

	// if ((rv = nng_listen(sock, _CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
	// 	nng_close(sock);
	// 	umask(22);
    //     return -1;
	// }
	

	// Now we've claimed the socket, dispatch thread to monitor it.
    if (pthread_create(&thid, NULL, socket_thread, NULL) != 0) {
        perror("pthread_create() error");
        return -EIO;
    }

    return 0;
}

int close_socket(void) {
    void *ret;
    running = false;
    if (pthread_join(thid, &ret) != 0) {
        perror("pthread_join() error");
        return -EIO;
    }
    return 0;
}