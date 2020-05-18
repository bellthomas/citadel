
#include <citadel/citadel.h>

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
	return 0;
}
