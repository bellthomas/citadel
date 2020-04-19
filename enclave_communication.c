#include "includes/enclave_communication.h"

static unsigned char current_challenge[64];

void* generate_challenge(size_t *len) {
    struct trm_challenge *challenge;
    char *encrypted, *challenge_hex, *hexstring, *hexstring2;
    int encrypted_len;

    challenge = kzalloc(sizeof(struct trm_challenge), GFP_KERNEL);
    if (!challenge) return NULL;

    // Set the signature and challenge.
    memcpy(challenge->signature, challenge_signature, sizeof(challenge_signature));
    get_random_bytes(current_challenge, sizeof(current_challenge));
    memcpy(challenge->challenge, current_challenge, sizeof(current_challenge));
    memset(challenge->name, 0, sizeof(challenge->name));
    memset(challenge->key, 0, sizeof(challenge->key));
    // memset(challenge->padding, 1, sizeof(challenge->padding));
    challenge->pid = (pid_t)0;

    challenge_hex = to_hexstring((unsigned char*)current_challenge, sizeof(current_challenge));
    printk(PFX "Generated a new challenge. (%s)\n", challenge_hex);
    kfree(challenge_hex);
    
    
    hexstring = to_hexstring((unsigned char*)challenge, sizeof(struct trm_challenge));
    printk(PFX "Data: %s\n", hexstring);
    kfree(hexstring);

    // Encrypt.
    encrypted = trm_rsa_encrypt((char*)challenge, sizeof(struct trm_challenge), &encrypted_len);
    kfree(challenge);
    
    hexstring2 = to_hexstring((unsigned char*)encrypted, encrypted_len);
    printk(PFX "Encrypted: %s\n", hexstring2);
    kfree(hexstring2);

    // if (!encrypted || encrypted_len <= 0) return NULL;
    
    *len = (size_t)encrypted_len;
    return encrypted;
}


// int challenge_response(void* received_data, size_t received_len) {
//     if(recevied_len != sizeof(struct trm_challenge)) return -2;


// }

// void update_requested(void);
// void update_received(void);
