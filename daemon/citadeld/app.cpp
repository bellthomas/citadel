
#include "includes/app.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
static bool running = true;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

sgx_enclave_id_t get_enclave_id(void) {
    return global_eid;
}

void signal_handler(int s) {
    printf("\nRequesting termination.\n");
    running = false;
}


int main(int argc, char const *argv[]) {
    if (argc < 2) {
        printf("Need to specify the enclave library to use.\n");
        return -1;
    }

    printf("---\nCitadel enclave: %s\n", argv[1]);
    int created_enclave = initialize_enclave(&global_eid, "enclave.token", argv[1]);
    if (created_enclave < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return created_enclave;
    }


    // Catch Ctrl+C and systemd stop commands.
    struct sigaction interrupt_handler;
    interrupt_handler.sa_handler = signal_handler;
    sigemptyset(&interrupt_handler.sa_mask);
    interrupt_handler.sa_flags = 0;
    sigaction(SIGINT, &interrupt_handler, NULL);
    sigaction(SIGTERM, &interrupt_handler, NULL);
    
    // Start receiving socket.
    if (!SUCCESS(initialise_socket())) {
        perror("Aborting. Failed to create socket");
        printf("Terminated.\n---\n");
        return -EIO;
    }
    
    // Initialise with LSM.
    if (lsm_register()) {
        printf("---\n");
        protect_socket(get_enclave_id());
        identifier_cache_setup();

        // Main execution loop.
        sgx_status_t pulse_res;
        while(running) {
            pulse_res = timer_pulse(global_eid);
            sleep(10);
        }
    }
    else {
        printf("Failed to register with the LSM.\n---\n");
    }

    // Begin termination sequence.
    printf("\nTerminating...\n");

    // First stop listening on the ingress socket.
    if (!SUCCESS(close_socket())) {
        printf("Error. Socket not closed cleanly. Continuing..\n");
    }
    printf("* Closed socket.\n");


    // Save state.
    // TODO
    printf("* State saved.\n");

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    global_eid = 0;
    printf("* Enclave destroyed.\n");

    return 0;
}
