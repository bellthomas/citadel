#include <citadel/citadel.h>
#include <citadel/shim.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h> 
#include <stdio.h> 
#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <string.h> 


#include "../includes/benchmarking.h"

static int repetitions = 1000000;


void run_benchmarks(void) {
	FILE *fp;
	fp = fopen("/opt/citadel-perf/libcitadel-benchmarks", "a");
	if(!fp) return;

	printf("1. citadel_init()\n");
	uint64_t diff;
	struct timespec start, end;
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_init();
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_init,%llu\n", (long long unsigned int) diff);
	}

	
	sleep(1);
	printf("2. citadel_claim()\n");

	const char path[] = "/opt/testing_dir/userspace_file.txt";
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_file_claim_force((char*)path, sizeof(path));
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_claim,%llu\n", (long long unsigned int) diff);
	}

	sleep(1);
	printf("3. citadel_open()\n");
	for (int i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		citadel_file_open((char*)path, sizeof(path));
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(fp, "citadel_open,%llu\n", (long long unsigned int) diff);
	}

	fclose(fp);
}

static void run_native_benchmarks(void) {
	errno = 0;
	uint64_t diff;
	struct timespec start, end;
	int i, bytes;
	char buff[100000] = {0};
	const char file[] = "/opt/untainted/test3.txt";

	FILE *log;
	int fd;
	FILE * fp;
	log = fopen("/opt/citadel-perf/native_benchmarks", "a");
	if(!log) return;

	printf("prep errno: %d\n", errno);
	errno = 0;

	// fork
	// pid_t pid;
	// for (int i = 0; i < repetitions; i++) {
	// 	clock_gettime(CLOCK_MONOTONIC, &start);
	// 	pid = fork();
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	if (pid == 0) exit(0);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	fprintf(log, "fork,%llu\n", (long long unsigned int) diff);
	// 	fflush(log);
	// }
	// printf("fork errno: %d\n", errno);
	// errno = 0;

	// open, read + write.
	for (i = 0; i < repetitions; i++) {
		//open
		clock_gettime(CLOCK_MONOTONIC, &start);
		fd = open(file, O_RDWR, 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "open,%llu\n", (long long unsigned int) diff);

		// // write
		// clock_gettime(CLOCK_MONOTONIC, &start);
		// bytes = write(fd, buff, sizeof(buff));
		// clock_gettime(CLOCK_MONOTONIC, &end);
		// diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "write,%llu\n", (long long unsigned int) diff);

		// lseek(fd, 0, SEEK_SET);

		// // read
		// clock_gettime(CLOCK_MONOTONIC, &start);
		// bytes = read(fd, buff, sizeof(buff));
		// clock_gettime(CLOCK_MONOTONIC, &end);
		// diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// if (bytes > 0) fprintf(log, "read,%llu\n", (long long unsigned int) diff);
		// fflush(log);

		if (fd) {
			clock_gettime(CLOCK_MONOTONIC, &start);
			close(fd);
			clock_gettime(CLOCK_MONOTONIC, &end);
			diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
			fprintf(log, "close,%llu\n", (long long unsigned int) diff);
		}
		fflush(log);
	}
	printf("open errno: %d\n", errno);
	errno = 0;
	return;

	// Socket.
	struct sockaddr_in address; 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons(12345); 
	int connector;
	for (i = 0; i < repetitions; i++) {
		//open
		clock_gettime(CLOCK_MONOTONIC, &start);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "socket,%llu\n", (long long unsigned int) diff);
		fflush(log);


		// Forcefully attaching socket to the port 8080 
		clock_gettime(CLOCK_MONOTONIC, &start);
    	if (bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
			perror("bind failed");
			continue;
		} 
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "bind,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		if (listen(fd, 3) < 0) { 
			perror("listen"); 
			continue;
		} 
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "listen,%llu\n", (long long unsigned int) diff);
		fflush(log);

		// Do connect.
		connector = socket(AF_INET, SOCK_STREAM, 0);
		clock_gettime(CLOCK_MONOTONIC, &start);
		if(connect(connector, (struct sockaddr *)&address, sizeof(address)) < 0) {
			close(connector);
			perror("connect"); 
			continue;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "connect,%llu\n", (long long unsigned int) diff);
		fflush(log);

		if (connector) close(connector);
		connector = 0;

		if (fd) close(fd);
		fd = 0;


	}
	printf("socket errno: %d\n", errno);
	errno = 0;

	int shmid;
	void *data;
	struct shmid_ds buf;
	errno = 0;
	key_t key = ftok("/tmp", 1);
	for (i = 0; i < repetitions; i++) {
		//open
		clock_gettime(CLOCK_MONOTONIC, &start);
		shmid = shmget(key, sizeof(uint32_t), IPC_CREAT | 0666);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmget,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		data = shmat(shmid, NULL, 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmat,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		shmctl(shmid, IPC_STAT, &buf);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmctl,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		shmdt(data);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmdt,%llu\n", (long long unsigned int) diff);
		fflush(log);

		shmctl(shmid, IPC_RMID, NULL);
	}
	printf("shm errno: %d\n", errno);
	errno = 0;

	int fds[2];
	for (i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		pipe(fds);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "pipe,%llu\n", (long long unsigned int) diff);
		fflush(log);

		if(fds[0]) close(fds[0]);
		if(fds[1]) close(fds[1]);
	}
	printf("pipe errno: %d\n", errno);
	errno = 0;

	for (i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		mkfifo("/tmp/testing_fifo", 0666);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "mkfifo,%llu\n", (long long unsigned int) diff);
		fflush(log);

		unlink("/tmp/testing_fifo");
	}
	printf("fifo errno: %d\n", errno);
	errno = 0;

	bool x;
	for (i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		x = citadel_init();
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "citadel_init,%llu\n", (long long unsigned int) diff);
		fflush(log);
	}
	printf("init errno: %d\n", errno);
	errno = 0;
}

static void run_tainted_benchmarks(void) {
	printf("asdasd\n");
	errno = 0;
	uint64_t diff;
	struct timespec start, end;
	int i, bytes;
	char buff[100000] = {0};
	const char file[] = "/opt/tainted/test.txt";


	bool citadel_pty_access = citadel_pty();
	if (!citadel_pty_access) {
		printf("Citadel failed to get PTY access.\n");
		exit(1);
	}

	// Force taint.
	int taintedfd = c_open(file, O_RDWR, 0666);
	if (taintedfd == -1) {
		exit(1);
	}
	c_close(taintedfd);


	FILE *log;
	int fd;
	FILE * fp;
	log = c_fopen("/opt/citadel-perf/citadel_benchmarks6", "a");
	if(!log)  {
		printf("%p %d\n", log, errno);
		return;
	}

	printf("prep errno: %d\n", errno);
	errno = 0;

	// fork
	// pid_t pid;
	// for (int i = 0; i < repetitions; i++) {
	// 	clock_gettime(CLOCK_MONOTONIC, &start);
	// 	pid = c_fork();
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	if (pid == 0) exit(0);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	fprintf(log, "fork,%llu\n", (long long unsigned int) diff);
	// 	fflush(log);
	// }
	// printf("fork errno: %d\n", errno);
	// errno = 0;

	// open, read + write.
	// for (i = 0; i < repetitions; i++) {
	// 	//open
	// 	clock_gettime(CLOCK_MONOTONIC, &start);
	// 	fd = c_open(file, O_RDWR, 0);
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	fprintf(log, "open,%llu\n", (long long unsigned int) diff);

	// 	// write
	// 	clock_gettime(CLOCK_MONOTONIC, &start);
	// 	bytes = c_write(fd, buff, sizeof(buff));
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	fprintf(log, "write,%llu\n", (long long unsigned int) diff);

	// 	lseek(fd, 0, SEEK_SET);

	// 	// read
	// 	clock_gettime(CLOCK_MONOTONIC, &start);
	// 	bytes = c_read(fd, buff, sizeof(buff));
	// 	clock_gettime(CLOCK_MONOTONIC, &end);
	// 	diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 	if (bytes > 0) fprintf(log, "read,%llu\n", (long long unsigned int) diff);
	// 	fflush(log);

	// 	if (fd) {
	// 		clock_gettime(CLOCK_MONOTONIC, &start);
	// 		c_close(fd);
	// 		clock_gettime(CLOCK_MONOTONIC, &end);
	// 		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
	// 		fprintf(log, "close,%llu\n", (long long unsigned int) diff);
	// 		fflush(log);
	// 	}
		
	// }
	// printf("open errno: %d\n", errno);
	// errno = 0;

	// Socket.
	struct sockaddr_in address; 
	address.sin_family = AF_INET; 
	address.sin_addr.s_addr = INADDR_ANY; 
	address.sin_port = htons(12345); 
	int connector;
	for (i = 0; i < repetitions; i++) {
		//open
		clock_gettime(CLOCK_MONOTONIC, &start);
		fd = socket(AF_INET, SOCK_STREAM, 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "socket,%llu\n", (long long unsigned int) diff);
		fflush(log);


		// Forcefully attaching socket to the port 8080 
		clock_gettime(CLOCK_MONOTONIC, &start);
    	if (c_bind(fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
			perror("bind failed");
			continue;
		} 
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "bind,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		if (c_listen(fd, 3) < 0) { 
			perror("listen"); 
			continue;
		} 
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "listen,%llu\n", (long long unsigned int) diff);
		fflush(log);

		// Do connect.
		connector = socket(AF_INET, SOCK_STREAM, 0);
		clock_gettime(CLOCK_MONOTONIC, &start);
		if(c_connect(connector, (struct sockaddr *)&address, sizeof(address)) < 0) {
			close(connector);
			perror("connect"); 
			continue;
		}
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		// fprintf(log, "connect,%llu\n", (long long unsigned int) diff);
		fflush(log);

		if (connector) close(connector);
		connector = 0;

		if (fd) close(fd);
		fd = 0;


	}
	printf("socket errno: %d\n", errno);
	errno = 0;
	return;

	int shmid;
	void *data;
	struct shmid_ds buf;
	errno = 0;
	key_t key = ftok("/tmp", 1);
	for (i = 0; i < repetitions; i++) {
		//open
		clock_gettime(CLOCK_MONOTONIC, &start);
		shmid = c_shmget(key, sizeof(uint32_t), IPC_CREAT | 0666);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmget,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		data = c_shmat(shmid, NULL, 0);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmat,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		c_shmctl(shmid, IPC_STAT, &buf);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmctl,%llu\n", (long long unsigned int) diff);
		fflush(log);

		clock_gettime(CLOCK_MONOTONIC, &start);
		shmdt(data);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "shmdt,%llu\n", (long long unsigned int) diff);
		fflush(log);

		shmctl(shmid, IPC_RMID, NULL);
	}
	printf("shm errno: %d\n", errno);
	errno = 0;

	int fds[2];
	for (i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		pipe(fds);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "pipe,%llu\n", (long long unsigned int) diff);
		fflush(log);

		if(fds[0]) close(fds[0]);
		if(fds[1]) close(fds[1]);
	}
	printf("pipe errno: %d\n", errno);
	errno = 0;

	for (i = 0; i < repetitions; i++) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		c_mkfifo("/tmp/testing_fifo", 0666);
		clock_gettime(CLOCK_MONOTONIC, &end);
		diff = 1000000000L * (end.tv_sec - start.tv_sec) + end.tv_nsec - start.tv_nsec;
		fprintf(log, "mkfifo,%llu\n", (long long unsigned int) diff);
		fflush(log);

		unlink("/tmp/testing_fifo");
	}
	printf("fifo errno: %d\n", errno);
	errno = 0;

}


void run_shim_benchmarks(void) {
	// run_native_benchmarks();
	run_tainted_benchmarks();
}
