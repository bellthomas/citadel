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
    unsigned char challenge_buffer[_TRM_RSA_KEY_LENGTH], response_buffer[_TRM_RSA_KEY_LENGTH];
    FILE *f_challenge, *f_response;

    pid_t pid = getpid();
    printf("Process ID: %d\n", pid);

    // Read challenge.
    f_challenge = fopen("/sys/kernel/security/trm/challenge", "rb");
    size_t challenge_read = fread(challenge_buffer, sizeof(challenge_buffer), 1, f_challenge);
    fclose(f_challenge);
    
    // Pass challenge to enclave.
    int status = handle_kernel_challenge(get_enclave_id(), &challenge_ecall_ret, challenge_buffer, _TRM_RSA_KEY_LENGTH, response_buffer, _TRM_RSA_KEY_LENGTH, (int32_t)pid);
    if (!challenge_ecall_ret) printf("Successfully registered with LSM.\n");
    
    // Pass cipher to LSM.
    int reg_res = send_registration(response_buffer, (size_t)_TRM_RSA_KEY_LENGTH);
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
    // printf("Installing ticket of length %lu\n", ticket_length);
    return send_update(ticket_data, ticket_length);
}

int trigger_process_updates() {

    FILE *f_update;
    f_update = fopen("/sys/kernel/security/trm/update", "rb");

    char buffer[4096];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), f_update);
    fclose(f_update);


    int updates_res;
    sgx_status_t updates_success = process_updates(get_enclave_id(), &updates_res, (uint8_t*)buffer, bytes_read); 

    // memcpy(ticket_data, buffer, bytes_read);


    return updates_res;
}


// xattr IO.
int install_xattr(char *path, size_t path_length, uint8_t *ticket_data, size_t ticket_length) {
    printf("Path: %s\n", path);
    setxattr(path, "security.citadel.install", ticket_data, ticket_length, 0);
    int res = errno; 
    printf("xattr_install return value: %d\n", res);
    errno = 0;

    // Testing.
    removexattr(path, "security.citadel.in_realm");
    res = errno; 
    printf("xattr_install return value: %d\n", res);
    errno = 0;
    //

    return res;
}