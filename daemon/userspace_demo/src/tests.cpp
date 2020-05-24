#include <citadel/citadel.h>
#include <time.h>
#include <sys/socket.h> 
#include <sys/types.h>
#include <sys/xattr.h>
#include <netinet/in.h> 
#include <sys/un.h>

#include "../includes/app.h"
#include "../includes/tests.h"

const char path[] = "/opt/testing_dir/userspace_file.txt";

void run_init(void) {
	bool citadel_ready = citadel_init();
	if (!citadel_ready) {
		printf("Citadel failed to init.\n");
		exit(1);
	}
}

void run_taint(void) {
	// Open file.
	bool citadel_file_open_ret = citadel_file_open((char*)path, sizeof(path));
	if (!citadel_file_open_ret) {
		printf("Can't open file.\n");
		exit(3);
	}

	FILE *fp;
	fp = fopen(path, "rw");
	if(fp) {
		printf("Tainted.\n\n");
		fclose(fp);
	}
	else printf("Failed to taint\n");
}

void run_pty(void) {
	bool citadel_pty_access = citadel_pty();
	if (!citadel_pty_access) {
		printf("Citadel failed to get PTY access.\n");
		exit(1);
	}
}

void run_file_test(void) {
	printf("Running file test...\n");

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


void run_socket_e_test(void) {
	printf("running socket test...\n");
	int server_fd, new_socket, valread; 
    struct sockaddr_in address; 
    int opt = 1; 
    // char buffer[1024] = {0}; 
    // char *hello = "Hello from server"; 
       
       
    // Creating socket file descriptor 
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

	
	// Set options.
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt))) 
    { 
        perror("setsockopt"); 
        exit(EXIT_FAILURE); 
    } 
    address.sin_family = AF_INET; 
    address.sin_addr.s_addr = INADDR_ANY; 
    address.sin_port = htons(13756); 
       
	bool socket_allowed = citadel_socket(server_fd, (struct sockaddr *)&address);

    // Bind to address. 
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
        perror("bind failed"); 
        // exit(EXIT_FAILURE); 
    }
	else {
		printf("Successfully bound to socket\n");
	}




	// struct sockaddr_un addr;
	// memset(&addr, 0, sizeof(addr));
	// addr.sun_family = AF_UNIX;
	// strncpy(addr.sun_path, "socket", sizeof(addr.sun_path)-1);
	// bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	while(on_hold()) {}
	reset_hold();
	close(server_fd);
}

void run_socket_i_test(void) {
	const char *socket_path = "/tmp/socket";

    // Creating socket file descriptor 
	int server_fd, child_fd;
    if ((server_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) 
    { 
        perror("socket failed"); 
        exit(EXIT_FAILURE); 
    } 

	struct sockaddr_un address;
	memset(&address, 0, sizeof(address));
	address.sun_family = AF_UNIX;
	strncpy(address.sun_path, socket_path, sizeof(address.sun_path)-1);


	bool socket_allowed = citadel_socket(server_fd, (struct sockaddr *)&address);

    // Bind to address. 
    if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
        perror("bind failed"); 
        // exit(EXIT_FAILURE); 
    }
	else {
		printf("Successfully bound to socket\n");
	}


	if (fork() == 0) {
		// Child
		if ((child_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) 
		{ 
			perror("child socket failed"); 
			exit(EXIT_FAILURE); 
		} 
	}
	else {
		// Parent
	}




	// struct sockaddr_un addr;
	// memset(&addr, 0, sizeof(addr));
	// addr.sun_family = AF_UNIX;
	// strncpy(addr.sun_path, "socket", sizeof(addr.sun_path)-1);
	// bind(fd, (struct sockaddr*)&addr, sizeof(addr));

	while(on_hold()) {}
	reset_hold();
	close(server_fd);
	unlink(socket_path);
}