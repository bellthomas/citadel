#include <sys/types.h>
#include <unistd.h>

#include "../include/citadel/shim.h"
#include "../include/citadel/citadel.h"

pid_t c_fork(void) {
    pid_t res = fork();
    if (res == 0) {
        // Child process.
        bool citadel_ready = citadel_init();
        if (!citadel_ready) {
            citadel_printf("[Shim] Citadel failed to init.\n");
            // exit(1);
        }
    }
    return res;
}
