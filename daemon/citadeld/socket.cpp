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
#include <sys/uio.h>

static pthread_t thid;
static int socket_fd = -1;
static bool running = true;
static long long int num_requests = 0;
static int ipc_timeout = 100 * 1000;

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

void send_response(int client_fd, char *message, size_t message_len) {
	uint8_t ecall_ret;
	uint8_t ptoken[_CITADEL_PROCESS_PTOKEN_LENGTH];
	bool cache_stage, valid_size;
	struct citadel_op_reply *reply;
	uint64_t pid = 0;
	int rv = 0;
	size_t sent = 0;
	int attempts = 0;

	// Get PID.
	struct ucred cred;
	socklen_t len = sizeof(struct ucred);
	getsockopt(client_fd, SOL_SOCKET, SO_PEERCRED, (void*)&cred, &len);
	pid = cred.pid;

	// Check length;
	valid_size = (message_len == sizeof(struct citadel_op_request)) || (message_len == sizeof(struct citadel_op_extended_request));

	// Process request.
	ecall_ret = valid_size ? CITADEL_OP_ERROR : CITADEL_OP_INVALID; // Default.
	cache_stage = valid_size ? cache_passthrough(message, message_len) : false;
	if (cache_stage) {
		handle_request(get_enclave_id(), &ecall_ret, (uint8_t*)message, message_len, (int32_t)pid, ptoken, sizeof(ptoken));
	}

	// Copy result into buffer to return to caller.
	if (message_len == sizeof(struct citadel_op_extended_reply)) {
		struct citadel_op_extended_reply *extended_reply = (struct citadel_op_extended_reply *)message;
		reply = &extended_reply->reply;
	} else {
		reply = (struct citadel_op_reply *)message;
	}
	memcpy(reply->ptoken, ptoken, _CITADEL_PROCESS_PTOKEN_LENGTH);
	reply->result = ecall_ret;


	while (attempts < ipc_timeout) {
		rv = write(client_fd, (const void*)reply, message_len);
		sent += (rv > 0 ? rv : 0);
		if (rv == -1 && (sent < message_len || (errno == EWOULDBLOCK || errno == EAGAIN))) {
			// usleep(1);
			attempts++;
			if(attempts >= ipc_timeout) {
				printf("Timed out. Failed to send. %s\n", strerror(errno));
				break;
			}
		}

		else if (sent == message_len) {
			break;
		}
		else if (rv < 0) {
			printf("Error, %s\n", strerror(errno));
			break;
		}
	}

	// rv = write(client_fd, (char*)reply, message_len);
	// sent += (rv > 0 ? rv : 0);
	// printf("asd");

	// rv = nng_sendmsg(sock, msg, NNG_FLAG_ALLOC);
	// nng_aio_set_msg(ap2, msg);
	// nng_send_aio(sock, ap2);
	// nng_aio_wait(ap2);
	// rv = nng_aio_result(ap2);
	// if (rv != 0) {
	// 	printf("nng_send failed\n");
	// 	nng_msg_free(msg);
	// }
}

void handle_client_socket(int client_fd) {
	size_t rv = 0;
	int attempts = 0;
	size_t received = 0;
	char buffer[sizeof(struct citadel_op_extended_request)];

	while (attempts < ipc_timeout) {
		rv = read(client_fd, (char*)buffer, sizeof(buffer));
		received += (rv > 0 ? rv : 0);
		if (rv == -1 && (errno == EWOULDBLOCK || errno == EAGAIN)) {
			// usleep(1);
			attempts++;
			if(attempts >= ipc_timeout) {
				printf("Timed out. Nothing received.\n");
				break;
				// return false;
			} 
		} 
		else if (rv > 0) {
			send_response(client_fd, (char*)buffer, received);
			break;
		}
		// else if (rv > 0) {
		// 	printf("Partial read: %ld bytes\n", rv);
		// }
		else if (rv < 0) {
			printf("Error, %s\n", strerror(errno));
			break;
		}
	}

	close(client_fd);
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
		client_fd = accept(socket_fd, (struct sockaddr *)&client, (socklen_t*)&c);
		if (client_fd > 0) {
			// Got a connection.
			handle_client_socket(client_fd);
		}

		else if (client_fd == -1 && !(errno == EWOULDBLOCK || errno == EAGAIN)) {
			if (errno != EINTR)
				printf("Error %d: %s\n", errno, strerror(errno));
			else
				running = false;
		}

#if SOCKET_PERFORMANCE == 0
		struct timespec t;
   		t.tv_sec = 0;
   		t.tv_nsec = 1000;
		nanosleep(&t, &t);
#endif
	}

	// end = std::chrono::high_resolution_clock::now();
	// std::chrono::duration<double> diff = end-start;
	// std::cout << num_requests << " requests in " << std::chrono::duration_cast<std::chrono::microseconds>(diff).count() << " us\n";
	// nng_close(sock);
}



void *socket_thread(void *arg) {
    run_server();
    pthread_exit(NULL);
}



// External.

int initialise_socket(void) {

	if ((socket_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error\n");
		return false;
  	}

#if SOCKET_NON_BLOCKING == 1
	// Set non-blocking.
	int flags = fcntl(socket_fd, F_GETFL, 0);
	if (fcntl(socket_fd, F_SETFL, flags | O_NONBLOCK)) {
		perror("failed to make socket non blocking\n");
		return false;
	}
#endif

	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	strncpy(addr.sun_path, _CITADEL_IPC_FILE, sizeof(_CITADEL_IPC_FILE));
	unlink(_CITADEL_IPC_FILE);

	// Change permissions so anyone can read/write, then listen.
	umask(0);
	if (bind(socket_fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error\n");
		return false;
	}
	umask(22); // Default.

	// Mark as passive socket.
	listen(socket_fd, 5);


	// Now we've claimed the socket, dispatch thread to monitor it.
    if (pthread_create(&thid, NULL, socket_thread, NULL) != 0) {
        perror("pthread_create() error");
		close(socket_fd);
		unlink(_CITADEL_IPC_FILE);
        return -EIO;
    }

    return 0;
}

int close_socket(void) {
    void *ret;
    running = false;

	pthread_kill(thid, SIGINT);
    if (pthread_join(thid, &ret) != 0) {
        perror("pthread_join() error");
		close(socket_fd);
		unlink(_CITADEL_IPC_FILE);
        return -EIO;
    }
	close(socket_fd);
	unlink(_CITADEL_IPC_FILE);
    return 0;
}