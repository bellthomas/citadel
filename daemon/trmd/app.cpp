
#include "includes/app.h"
#include <nng/nng.h>
#include <pthread.h>

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

sgx_enclave_id_t get_enclave_id(void) {
    return global_eid;
}

void *thread(void *arg) {
    char *ret;

    strcpy(ret, "This is a test");
    pthread_exit(ret);
}

int main(int argc, char const *argv[]) {
    if (argc < 2) {
        printf("Need to specify the enclave library to use.\n");
        return -1;
    }

    printf("Citadel enclave: %s\n", argv[1]);
    if (initialize_enclave(&global_eid, "enclave.token", argv[1]) < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }

    pthread_t thid;
    void *ret;
    if (pthread_create(&thid, NULL, thread, NULL) != 0) {
        perror("pthread_create() error");
        exit(1);
    }

    if (pthread_join(thid, &ret) != 0) {
        perror("pthread_create() error");
        exit(3);
    }
    
    // Initialise with LSM.
    int reg_res = lsm_register();
    sgx_status_t pulse_res = timer_pulse(global_eid);


    // char *value = "Some testing value here kajshdkjahsdkjhaskjhakjhasdkjhas";
    // int updates_res = xattr_install("/opt/testing_dir/test", value, sizeof(value));
    while(1) {
        ;;
    }
    return 0;
}
