#include <citadel/citadel.h>
#include <time.h>
#include <sys/socket.h> 

#include "../includes/tests.h"

const char path[] = "/opt/testing_dir/userspace_file.txt";

void run_taint(void) {
	// On start.
	bool citadel_ready = citadel_init();
	if (!citadel_ready) {
		printf("Citadel failed to init.\n");
		exit(1);
	}

	// Open file.
	bool citadel_file_open_ret = citadel_file_open((char*)path, sizeof(path));
	if (!citadel_file_open_ret) {
		printf("Can't open file.\n");
		exit(3);
	}

	FILE *fp;
	fp = fopen(path, "rw");
	if(fp) fclose(fp);
	else printf("Failed to taint\n");
}

void run_file_test(void) {
    // On start.
	bool citadel_ready = citadel_init();
	if (!citadel_ready) {
		printf("Citadel failed to init.\n");
		exit(1);
	}

	// Init file.
	bool citadel_file_create_ret = citadel_file_create((char*)path, sizeof(path));
	if (!citadel_file_create_ret) {
		printf("Citadel failed to create file.\n");
		exit(2);
	}

	// Open file.
	bool citadel_file_open_ret = citadel_file_open((char*)path, sizeof(path));
	if (!citadel_file_open_ret) {
		printf("Can't open file.\n");
		exit(3);
	}

	FILE *fp;
	fp = fopen(path, "rw");
	if(fp) {
		printf("Opened file (1)\n");
		fprintf(fp, "%d", 1);
		fclose(fp);
	}
	else printf("Failed to open file (1)\n");

	sleep(10);
	fp = fopen(path, "r");
	if(fp) {
		printf("Opened file (2)\n");
		// fprintf(fp, "%d", 2);
		fclose(fp);
	}
	else printf("Failed to open file (2)\n");

	sleep(10);
	fp = fopen(path, "w");
	if(fp) {
		printf("Opened file (3)\n");
		fprintf(fp, "%d", 3);
		fclose(fp);
	}
	else printf("Failed to open file (3)\n");

	citadel_file_create_ret = citadel_file_open((char*)path, sizeof(path));
	if (!citadel_file_create_ret) {
		printf("Citadel failed to create file.\n");
		exit(3);
	}

	fp = fopen(path, "r");
	if(fp) {
		printf("Opened file (4)\n");
		fprintf(fp, "%d", 4);
		fclose(fp);
	}
	else printf("Failed to open file (4)\n");
}


void run_socket_test(void) {
	int server_fd; 
    // struct sockaddr_in address; 
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

	printf("Socket FD: %d\n", server_fd);
	while(1) {}
	close(server_fd);
}