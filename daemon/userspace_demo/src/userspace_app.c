
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
	fclose(fp);

	sleep(10);
	fp = fopen(path, "rw");
	fclose(fp);

	sleep(10);
	fp = fopen(path, "a");
	fclose(fp);
	return 0;
}
