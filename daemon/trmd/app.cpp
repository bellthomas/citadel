
#include "includes/app.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

sgx_enclave_id_t get_enclave_id(void) {
    return global_eid;
}


int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "build/trm.basic.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    
    // Initialise with LSM.
    int reg_res = lsm_register();
    sgx_status_t pulse_res = timer_pulse(global_eid);
    // int updates_res = trigger_process_updates();
    return 0;
}
