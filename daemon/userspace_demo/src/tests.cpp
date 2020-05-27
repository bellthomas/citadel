#include <citadel/citadel.h>
#include <citadel/shim.h>
#include <time.h>
#include <sys/socket.h> 
#include <sys/types.h>
#include <sys/xattr.h>
#include <netinet/in.h> 
#include <sys/un.h>
#include <stdio.h> 
#include <string.h> 
#include <fcntl.h> 
#include <sys/stat.h> 
#include <unistd.h> 
#include <sys/ipc.h>
#include <sys/shm.h>

#include "../includes/app.h"
#include "../includes/tests.h"

const char path[] = "/opt/testing_dir/userspace_file.txt";
const char path2[] = "/opt/testing_dir/userspace_file_2.txt";

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
	else printf("Failed to taint.\n");
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
	bool citadel_file_create_ret = citadel_file_claim((char*)path, sizeof(path));
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
       
	// bool socket_allowed = citadel_socket(server_fd, (struct sockaddr *)&address);

    // Bind to address. 
    if (c_bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
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

	// bool socket_allowed = citadel_socket(server_fd, (struct sockaddr *)&address);

    // Bind to address. 
    if (c_bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
        perror("bind failed"); 
		return;
        // exit(EXIT_FAILURE); 
    }
	else {
		printf("Successfully bound to socket\n");
	}

	// bool citadel_file_create_ret = citadel_file_claim_force((char*)socket_path, sizeof(path));
	// bool citadel_file_open_ret = citadel_file_open((char*)socket_path, sizeof(path));

	listen(server_fd, 5);


	if (c_fork() == 0) {

		// Child
		if ((child_fd = socket(AF_UNIX, SOCK_STREAM, 0)) == 0) 
		{ 
			perror("child socket failed"); 
			exit(EXIT_FAILURE); 
		} 

		// bool socket_allowed = citadel_socket(child_fd, (struct sockaddr *)&address);
		// bool citadel_file_open_ret = citadel_file_open((char*)socket_path, sizeof(path));

		// Bind to address. 
		if (c_connect(child_fd, (struct sockaddr *)&address, sizeof(address)) < 0) { 
			perror("connect failed"); 
			// exit(EXIT_FAILURE); 
		}
		else {
			printf("Successfully bound to socket\n");
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


void run_pipe_test(void) {
	int     fd[2], nbytes;
	pid_t   childpid;
	char    string[] = "Hello, world!\n";
	char    readbuffer[80];

	pipe(fd);
	
	if((childpid = c_fork()) == -1) {
		perror("fork");
		return;
	}

	if(childpid == 0)
	{
		/* Child process closes up input side of pipe */
		close(fd[0]);

		bool can_have_parent_pipe = citadel_parent_pipe();
		if (!can_have_parent_pipe) {
			printf("Citadel failed to get pipe access.\n");
		}

		/* Send "string" through the output side of pipe */
		write(fd[1], string, (strlen(string)+1));
		return;
	}
	else
	{
		/* Parent process closes up output side of pipe */
		close(fd[1]);

		/* Read in a string from the pipe */
		nbytes = read(fd[0], readbuffer, sizeof(readbuffer));
		printf("Received string: %s", readbuffer);
	}
	
	while(on_hold()) {}
	reset_hold();
	return;
}

void run_fifo_test(void) {
	int fdp, fdc; 
    const char myfifo[] = "/tmp/myfifo"; 
  
    // Creating the named file (FIFO) 
    if (mkfifo(myfifo, 0666)) {
		printf("Failed to make FIFO.\n");
		return;
	}

	bool citadel_file_create_ret = citadel_file_claim((char*)myfifo, sizeof(myfifo));
	if (!citadel_file_create_ret) {
		printf("Citadel failed to claim file.\n");
		unlink(myfifo);
		return;
	}

	if (c_fork() == 0) { 
		// Child
		citadel_file_create_ret = citadel_file_open((char*)myfifo, sizeof(myfifo));
		if (!citadel_file_create_ret) {
			printf("Child failed to open file.\n");
			return;
		} else {
			fdc = open(myfifo, O_RDONLY);
			if (fdc >= 0) {
				char buf[7];
				read(fdc, buf, 7);
				printf("Successfully opened file (child, write)\n");
				printf("%s\n", buf);
			} else {
				printf("Failed to open file (child, write)\n");
			}
		}
		while(on_hold()) {}
		close(fdc);
	}
	else {

		// citadel_file_create_ret = citadel_file_open((char*)myfifo, sizeof(myfifo));
		// if (!citadel_file_create_ret) {
		// 	printf("Child failed to open file.\n");
		// 	return;
		// } else
		{
			fdp = open(myfifo, O_WRONLY);
			if (fdc >= 0) {
				printf("Successfully opened file (parent, read)\n");
				write(fdp, "Hello!", 7);
			} else {
				printf("Failed to open file (parent, read)\n");
			}
		}
		while(on_hold()) {}
		close(fdp);
		unlink(myfifo);
	}
	reset_hold();
	return;
}

void run_shm_test(void) {
	key_t key;
    int shmid;
    char *data;
    int mode;


    /* make the key: */
    if ((key = ftok(path, 'R')) == -1) /*Here the file must exist */ 
	{
        perror("ftok");
        exit(1);
    }

	printf("SHM key: %d\n", key);


	bool allow_shm = citadel_shm_access(key);
	if (!allow_shm) {
		printf("Failed to get SHM.\n");
		return;
	}

    // /*  create the segment: */
    if ((shmid = shmget(key, 50, 0644 | IPC_CREAT)) == -1) {
        perror("shmget");
        exit(1);
    } else {
		printf("Success: shmget\n");
	}

    /* attach to the segment to get a pointer to it: */
    data = (char*)shmat(shmid, NULL, 0);
    if (data == (char *)(-1)) {
        perror("shmat");
        exit(1);
    } else {
		printf("Success: shmat\n");
	}

    // /* read or modify the segment, based on the command line: */
    // if (argc == 2) {
    //     printf("writing to segment: \"%s\"\n", argv[1]);
    //     strncpy(data, argv[1], SHM_SIZE);
    // } else
    //     printf("segment contains: \"%s\"\n", data);

    // /* detach from the segment: */
    if (shmdt(data) == -1) {
        perror("shmdt");
        exit(1);
    } else {
		printf("Success: shmdt\n");
	}

}