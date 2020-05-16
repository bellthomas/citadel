
#include "includes/userspace_io.h"

static unsigned char ptoken_aes_key[16] = {"\0"};

void set_ptoken_aes_key(unsigned char* key) {
    memcpy(ptoken_aes_key, key, sizeof(ptoken_aes_key));
}

// int aes_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen) {

int handle_request(uint8_t* data, size_t length) {
    // ocall_print("handle_request()");
    unsigned char decrypted[_TRM_PROCESS_SIGNED_PTOKEN_LENGTH + IV_LENGTH + TAG_LENGTH];
    size_t outlen = sizeof(decrypted);
    int aes_ret = aes_decrypt((unsigned char*)data, length, decrypted, &outlen, ptoken_aes_key, _TRM_AES_KEY_LENGTH);
    if(aes_ret) {
        ocall_print("Failed to decrypt");
        return -1;
    }

    if(outlen != sizeof(struct trm_ptoken_protected)) {
        ocall_print("Invalid size");
        return -1;
    }

    print_hex(decrypted, outlen);
    struct trm_ptoken_protected *ptoken = (struct trm_ptoken_protected *)decrypted;

    if(memcmp(ptoken->signature, challenge_signature, sizeof(challenge_signature))) {
        ocall_print("Signatures don't match...");
        return -1;
    }

    char buffer[100];
    int cx;
    cx = snprintf(buffer, sizeof(buffer), "PID: %d", ptoken->pid);
    ocall_print(buffer);


    return 0;
}
