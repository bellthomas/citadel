#include "includes/socket.h"

#include <iostream>
#include <chrono>

static pthread_t thid;
static nng_socket sock;
static bool running = true;
static long long int num_requests = 0;

void c_handle_message(char *buf, size_t sz) {
	int rv;
	// sleep(5);
	rv = nng_send(sock, buf, sz, NNG_FLAG_ALLOC);
	if (rv != 0) {
		printf("nng_send failed\n");
	}
	return;
}

void run_server(void) {
    int rv;

    if ((rv = nng_rep0_open(&sock)) != 0) {
		printf("nng_rep0_open fail\n");
        return;
	}

	// Change permissions so anyone can read/write.
	umask(0);

	if ((rv = nng_listen(sock, CITADEL_IPC_ADDRESS, NULL, 0)) != 0) {
		printf("nng_listen fail\n");
		umask(22);
        return;
	}
	umask(22); // Default.


	auto start = std::chrono::high_resolution_clock::now();
	auto end = std::chrono::high_resolution_clock::now();
	bool started = false;
    // nng_setopt_int(subs, NNG_OPT_RECVBUF, 100);
	// nng_setopt_ms(subs, NNG_OPT_RECONNMINT, 1000);
	// nng_setopt_ms(subs, NNG_OPT_RECONNMAXT, 0);

	while (running) {
		// char *buf;
		// size_t sz;
		// time_t now;

		nng_msg *msg;
		nng_pipe p;
		uint64_t pid = 0;
		void *message;
		size_t message_len;

		rv = nng_recvmsg(sock, &msg, NNG_FLAG_NONBLOCK);
		// rv = nng_recv(sock, &buf, &sz, NNG_FLAG_NONBLOCK | NNG_FLAG_ALLOC);

		switch (rv) {
		case NNG_EAGAIN:
			// Nothing this time.
			break;
		case 0:
			// rv = nng_send(sock, buf, sz, NNG_FLAG_ALLOC);
			// if (rv != 0) {
			// 	nng_free(buf, sz);
			// 	printf("nng_send failed\n");
			// }
			if (!started) {
				started = true;
				start = std::chrono::high_resolution_clock::now();
			}

			p = nng_msg_get_pipe(msg);
			nng_pipe_getopt_uint64(p, NNG_OPT_IPC_PEER_PID, &pid);
			// printf("Received message: %lu bytes from PID %ld\n", nng_msg_len(msg), pid);

			message = nng_msg_body(msg);
			message_len = nng_msg_len(msg);

			rv = nng_sendmsg(sock, msg, NNG_FLAG_ALLOC);
			if (rv != 0) {
				printf("nng_send failed\n");
				nng_msg_free(msg);
			}

			num_requests++;
			break;

		default:
			printf("GOT ERROR %s\n", nng_strerror(rv));
			return;
		}
		usleep(0.1);
	}

	end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double> diff = end-start;
	std::cout << num_requests << " requests in " << std::chrono::duration_cast<std::chrono::microseconds>(diff).count() << " us\n";
	nng_close(sock);
}



void *socket_thread(void *arg) {
    char *ret;

    // Main function.
    run_server();

    strcpy(ret, "This is a test");
    pthread_exit(ret);
}



// External.

int initialise_socket(void) {
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