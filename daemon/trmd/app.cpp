#include <stdio.h>
#include <iostream>
#include "Enclave_u.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"



/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

// OCall implementations
void ocall_print(const char* str) {
    printf("%s\n", str);
}

int main(int argc, char const *argv[]) {
    if (initialize_enclave(&global_eid, "enclave.token", "build/trm.basic.signed.so") < 0) {
        std::cout << "Fail to initialize enclave." << std::endl;
        return 1;
    }
    int ptr;
    sgx_status_t status = generate_random_number(global_eid, &ptr);
    std::cout << status << std::endl;
    if (status != SGX_SUCCESS) {
        std::cout << "noob" << std::endl;
    }
    // printf("Random number: %d\n", ptr);
    printf("\n\n\n");



    printf("Running challenge check.\n");

    unsigned char buffer[256];
    FILE *file;
    file = fopen("/sys/kernel/security/trm/challenge", "rb");
    size_t ss = fread(buffer, sizeof(buffer), 1, file);
    printf("Read %d bytes\n", ss*sizeof(buffer));
    // for(int i = 0; i < 256; i++)
    //     printf("%h", buffer[i]);
    sgx_status_t challenge_ecall_ret;
    status = challenge_read(global_eid, &challenge_ecall_ret, buffer, 256);
    printf("* %d\n\n", status);

    // printf("Running challenge check -- %s.\n", buffer);

    // Seal the random number
    size_t sealed_size = sizeof(sgx_sealed_data_t) + sizeof(ptr);
    uint8_t* sealed_data = (uint8_t*)malloc(sealed_size);

    sgx_status_t ecall_status;
    status = seal(global_eid, &ecall_status,
            (uint8_t*)&ptr, sizeof(ptr),
            (sgx_sealed_data_t*)sealed_data, sealed_size);

    if (!is_ecall_successful(status, "Sealing failed :(", ecall_status)) {
        return 1;
    }

    int unsealed;
    status = unseal(global_eid, &ecall_status,
            (sgx_sealed_data_t*)sealed_data, sealed_size,
            (uint8_t*)&unsealed, sizeof(unsealed));

    if (!is_ecall_successful(status, "Unsealing failed :(", ecall_status)) {
        return 1;
    }

    std::cout << "Seal round trip success! Receive back " << unsealed << std::endl;

    return 0;
}

