
#include "includes/userspace_io.h"

static unsigned char ptoken_aes_key[16] = {"\0"};

void set_ptoken_aes_key(unsigned char* key) {
    memcpy(ptoken_aes_key, key, sizeof(ptoken_aes_key));
}

// int aes_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen) {

uint8_t handle_request(uint8_t* data, size_t length, int32_t pid, uint8_t* ptoken, size_t ptoken_length) {
    
    // Before starting, check we have a valid ptoken output buffer.
    if (!ptoken || ptoken_length != _TRM_PROCESS_PTOKEN_LENGTH) {
        ocall_print("Output ptoken buffer too small.");
        return CITADEL_OP_ERROR;
    }

    // First, check that the payload size is correct.
    struct citadel_op_request *request = (struct citadel_op_request*)data;
    if (length != sizeof(struct citadel_op_request)) {
        ocall_print("Invalid request size.");
        return CITADEL_OP_INVALID;
    }

    // Next, check that the signature matches.
    if(memcmp(request->signature, challenge_signature, sizeof(challenge_signature))) {
        ocall_print("Invalid signature");
        return CITADEL_OP_INVALID;
    }

    // Then, try to decrypt the ptoken.
    size_t signed_payload_len = sizeof(struct trm_ptoken_protected) + IV_LENGTH + TAG_LENGTH;
    unsigned char decrypted[signed_payload_len];
    size_t outlen = signed_payload_len;
    int aes_ret = aes_decrypt((unsigned char*)request->signed_ptoken, signed_payload_len, decrypted, &outlen, ptoken_aes_key, _TRM_AES_KEY_LENGTH);
    if(aes_ret) {
        ocall_print("Failed to decrypt ptoken.");
        return CITADEL_OP_INVALID;
    }

    struct trm_ptoken_protected *ptoken_payload = (struct trm_ptoken_protected *)decrypted;

    // Check that the decrypted ptoken has the right size and signature.
    if(outlen != sizeof(struct trm_ptoken_protected)) {
        ocall_print("Invalid ptoken payload size.");
        return CITADEL_OP_INVALID;
    }

    if(memcmp(ptoken_payload->signature, challenge_signature, sizeof(challenge_signature))) {
        ocall_print("Invalid ptoken signature.");
        return CITADEL_OP_INVALID;
    }

    // Check the PID reported by the IPC medium and signed in the payload.
    if (pid != ptoken_payload->pid) {
        ocall_print("Mismatching PIDs --- forged request.");
        return CITADEL_OP_FORGED;
    }
    
    // char buffer[100];
    // int cx;
    // cx = snprintf(buffer, sizeof(buffer), "* Verified PID: %d", ptoken->pid);
    // ocall_print(buffer);
    // generate_xattr_ticket();
    // generate_ticket(1);

    memcpy(ptoken, ptoken_payload->ptoken, ptoken_length);

    uint8_t result = asm_handle_request(request);

    // Install tickets if required.
    // if (result == )

    return result;
}
