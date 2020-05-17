
#include <citadel/citadel.h>

int main(void) {

	// On start.
	bool citadel_ready = citadel_init();
	if (!citadel_ready) {
		printf("Citadel failed to init.\n");
		exit(1);
	}

	return 0;
}
