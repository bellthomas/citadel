
#include "includes/lsm_communication.h"

static const unsigned char challenge_signature[8] = { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };

// Needs to be 214 bytes.
struct trm_challenge {
    unsigned char signature[8];
    unsigned char challenge[32];
    unsigned char name[40];
    unsigned char key[128];
    int pid; // pid_t
    unsigned char padding[2];
};

static unsigned char aes_key[128] = {"\0"};




sgx_status_t aes_encrypt_data(uint8_t* in_data, size_t in_length, uint8_t* out_data, size_t out_length) {
    return SGX_SUCCESS;
}


sgx_status_t handle_challenge_phase_1(uint8_t* challenge_data, size_t challenge_length, uint8_t* response_data, size_t response_length) {
    sgx_status_t status = SGX_SUCCESS; 

    // ocall_print("-- Challenge read");
    // print_hex(challenge_data, challenge_length);
    unsigned char decrypted[RSA_BLOCK_SIZE];
    struct trm_challenge *challenge;
    size_t decrypted_len = RSA_BLOCK_SIZE;
    int result;

    int err = rsa_decrypt(challenge_data, challenge_length, decrypted, &decrypted_len, &result, enclave_key_priv, enclave_key_priv_len);
    if (err != 0) return (sgx_status_t)err;
    // print_hex(decrypted, decrypted_len);

    // Check if its a trm_challenge.
    if (decrypted_len != sizeof(trm_challenge)) {
        ocall_print("Size of decrypted payload wrong.");
        return (sgx_status_t)decrypted_len;
    }

    challenge = (struct trm_challenge*)decrypted;
    if(memcmp(challenge->signature, challenge_signature, sizeof(challenge_signature))) {
        ocall_print("Signatures don't match...");
        return (sgx_status_t)-5;
    }

    // Got a valid decrypted challenge.
    char name[] = "trm.basic.so";
    memcpy(challenge->name, name, sizeof(name));
    sgx_read_rand(aes_key, 128);
    memcpy(challenge->key, aes_key, sizeof(aes_key));
    challenge->pid = 420;


    // ocall_print("-- Response write");
    // print_hex((unsigned char*)challenge, sizeof(trm_challenge));
    unsigned char cipher[RSA_BLOCK_SIZE];
    size_t outlen = RSA_BLOCK_SIZE;
    err = rsa_encrypt((unsigned char*)challenge, sizeof(trm_challenge), cipher, &outlen, lsm_key_padded_pub, lsm_key_padded_pub_len);
    if (err != 0) return (sgx_status_t)err;
    // print_hex(cipher, outlen);

    memcpy(response_data, cipher, response_length);

    return (sgx_status_t)0;
}