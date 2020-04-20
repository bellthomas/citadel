#include "includes/enclave_communication.h"

static unsigned char current_challenge[32];
static char registered_name[40];
static char aes_key[128];
static int registered = 0;

void* generate_challenge(size_t *len) {
    struct trm_challenge *challenge;
    char *encrypted, *challenge_hex; //, *hexstring, *hexstring2;
    int encrypted_len;

    challenge = kzalloc(sizeof(struct trm_challenge), GFP_KERNEL);
    if (!challenge) return NULL;

    // Set the signature and challenge.
    memcpy(challenge->signature, challenge_signature, sizeof(challenge_signature));
    get_random_bytes(current_challenge, sizeof(current_challenge));
    memcpy(challenge->challenge, current_challenge, sizeof(current_challenge));
    memset(challenge->name, 0, sizeof(challenge->name));
    memset(challenge->key, 0, sizeof(challenge->key));
    memset(challenge->padding, 1, sizeof(challenge->padding));
    challenge->pid = (pid_t)0;

    challenge_hex = to_hexstring((unsigned char*)current_challenge, sizeof(current_challenge));
    printk(PFX "Generated a new challenge.\n");
    kfree(challenge_hex);
    
    
    // hexstring = to_hexstring((unsigned char*)challenge, sizeof(struct trm_challenge));
    // printk(PFX "Data: %s\n", hexstring);
    // kfree(hexstring);

    // Encrypt.
    encrypted = trm_rsa_encrypt((char*)challenge, sizeof(struct trm_challenge), &encrypted_len);
    kfree(challenge);
    
    // hexstring2 = to_hexstring((unsigned char*)encrypted, encrypted_len);
    // printk(PFX "Encrypted: %s\n", hexstring2);
    // kfree(hexstring2);

    // if (!encrypted || encrypted_len <= 0) return NULL;
    
    *len = (size_t)encrypted_len;
    return encrypted;
}

void process_challenge_response(void *response, size_t response_len) {
    struct trm_challenge *challenge;
    size_t decrypted_len;
    // char *hex;

    if(response_len != RSA_PAYLOAD_SIZE) {
        printk(PFX "Rejected challenge response: invalid length (%ld)\n", response_len);
        goto bail;
    }

    challenge = (struct trm_challenge*) trm_rsa_decrypt((char*)response, response_len, (int*)&decrypted_len);
    // hex = to_hexstring((unsigned char*)challenge, sizeof(struct trm_challenge));
    // printk(PFX "Decrypted challenge: %s\n", hex);
    // kfree(hex);

    // Valid decrypted payload, check signature.
    if(memcmp(challenge->signature, challenge_signature, sizeof(challenge_signature))) {
        printk(PFX "Rejected challenge response: signature incorrect.\n");
        goto bail;
    }

    // Valid decrypted payload, check signature.
    if(memcmp(challenge->challenge, current_challenge, sizeof(current_challenge))) {
        printk(PFX "Rejected challenge response: challenge key incorrect.\n");
        goto bail;
    }

    // Challenge response successful.
    memcpy(registered_name, challenge->name, sizeof(registered_name));
    memcpy(aes_key, challenge->key, sizeof(aes_key));

    printk(PFX "Successfully registered with %s\n", registered_name);
    registered = 1;

bail: 
    if (challenge) kfree(challenge);
    return;
}


// int trm_aes_decrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen) {
//     return prepare_aead(key, data, datasize, AES_DECRYPT, out, outlen);
// }

// int trm_aes_encrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen) {
//     return prepare_aead(key, data, datasize, AES_ENCRYPT, out, outlen);
// }

void process_received_update(void *update, size_t update_len) {
    char *plain, *hex;
    size_t outlen;
    int res;

    if (!registered) {
        printk(PFX "Can't process update. Not registered.\n");
        return;
    }
    
    plain = kzalloc(update_len, GFP_KERNEL);
    outlen = update_len;
    res = trm_aes_decrypt(aes_key, update, update_len, plain, &outlen);

    hex = to_hexstring(plain, outlen);
    printk(PFX "Received plain: %s\n", hex);
    kfree(hex);
}


void* generate_update(size_t *len) {
    char msg[] = "This is some kind of update.";
    char *cipher, *hex;
    size_t outlen;
    int res;
    

    if (!registered) {
        printk(PFX "Can't generate update. Not registered.\n");
        *len = 0;
        return NULL;
    }

    cipher = kzalloc(sizeof(msg) + TAG_LENGTH, GFP_KERNEL);
    outlen = sizeof(msg) + TAG_LENGTH;
    res = trm_aes_encrypt(aes_key, msg, sizeof(msg), cipher, &outlen);

    hex = to_hexstring(cipher, outlen);
    printk(PFX "Generated cipher: %s\n", hex);
    kfree(hex);

    *len = outlen;
    return cipher;
}

// void update_requested(void);
// void update_received(void);
