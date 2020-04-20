#include "includes/lsm_io.h"

// Registration.


int send_registration(void *data, size_t datalen) {
    FILE *f_response;
    f_response = fopen("/sys/kernel/security/trm/challenge", "wb");
    size_t response_write = fwrite(data, datalen, 1, f_response);
    fclose(f_response);
    return (int)response_write;
}

int perform_registration(void) {
    sgx_status_t challenge_ecall_ret;
    unsigned char challenge_buffer[256], response_buffer[256];
    FILE *f_challenge, *f_response;

    // Read challenge.
    f_challenge = fopen("/sys/kernel/security/trm/challenge", "rb");
    size_t challenge_read = fread(challenge_buffer, sizeof(challenge_buffer), 1, f_challenge);
    fclose(f_challenge);
    
    // Pass challenge to enclave.
    int status = handle_challenge_phase_1(get_enclave_id(), &challenge_ecall_ret, challenge_buffer, 256, response_buffer, 256);
    printf("* %d\n", challenge_ecall_ret);
    
    // Pass cipher to LSM.
    int reg_res = send_registration(response_buffer, (size_t)256);
    return (int)challenge_ecall_ret;
}

int check_registration(void) {
    return 1;
}

int lsm_register(void) {
    int res = perform_registration();

    return res;
}


// Updates.

int send_update(void *data, size_t datalen) {
    FILE *f_update;
    f_update = fopen("/sys/kernel/security/trm/update", "wb");
    size_t wrote = fwrite(data, datalen, 1, f_update);
    fclose(f_update);
    return (int)wrote;
}

void test_aes(void) {
    char msg[] = "aes test message";
    char *cipher = (char*)malloc(sizeof(msg) + 16);
}


int install_ticket(uint8_t* ticket_data, size_t ticket_length) {
    printf("Installing ticket of length %lu\n", ticket_length);
    return send_update(ticket_data, ticket_length);
}

int process_updates(uint8_t* ticket_data, size_t ticket_length) {
    // FILE *f_update;
    // f_update = fopen("/sys/kernel/security/trm/update", "rb");

    // char buffer[4096];
    // size_t bytes_read = fread(buffer, 1, sizeof(buffer), f_update);
    // fclose(f_update);

    // memcpy(ticket_data, buffer, bytes_read);


    return 0;
}