
#include <citadel/citadel.h>
#include <time.h>


int main(void) {

	// On start.
	bool citadel_ready = citadel_init();
	if (!citadel_ready) {
		printf("Citadel failed to init.\n");
		exit(1);
	}

	// Init file.
	const char path[] = "/opt/testing_dir/userspace_file.txt";
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
	fp = fopen(path, "r");
	if(fp) {
		printf("Opened file (1)\n");
		fclose(fp);
	}
	else printf("Failed to open file (1)\n");

	sleep(10);
	fp = fopen(path, "rw");
	if(fp) {
		printf("Opened file (2)\n");
		fclose(fp);
	}
	else printf("Failed to open file (2)\n");

	sleep(10);
	fp = fopen(path, "a");
	if(fp) {
		printf("Opened file (3)\n");
		fclose(fp);
	}
	else printf("Failed to open file (3)\n");

	citadel_file_create_ret = citadel_file_open((char*)path, sizeof(path));
	if (!citadel_file_create_ret) {
		printf("Citadel failed to create file.\n");
		exit(3);
	}

	fp = fopen(path, "a");
	if(fp) {
		printf("Opened file (4)\n");
		fclose(fp);
	}
	else printf("Failed to open file (4)\n");
	return 0;
}
