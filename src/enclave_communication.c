#include "includes/enclave_communication.h"

static unsigned char current_challenge[32];
static char registered_name[40];
static char aes_key[16];
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


void update_aes_key(void *key, size_t key_len) {
    // char *h;
    int i;
    if(key_len >= sizeof(aes_key)) {
        for(i = 0; i < sizeof(aes_key); i++) {
            aes_key[i] = aes_key[i] ^ ((unsigned char*)key)[i];
        }
    }
    // h = to_hexstring(aes_key, sizeof(aes_key));
    // printk(PFX "** Updated AES key.\n");
    // printk(PFX "%s\n", h);
    // printk(PFX "**\n");
    // kfree(h);
}


void process_received_update(void *update, size_t update_len) {
    char *plain; //, *hex;
    size_t outlen;
    int res;
    struct trm_update_header *hdr;

    if (!registered) {
        printk(PFX "Can't process update. Not registered.\n");
        return;
    }
    
    plain = kzalloc(update_len, GFP_KERNEL);
    outlen = update_len;
    res = trm_aes_decrypt(aes_key, update, update_len, plain, &outlen);

    hdr = (struct trm_update_header*)plain;
    if(memcmp(hdr->signature, challenge_signature, sizeof(challenge_signature))) {
        printk(PFX "Rejected updates. Signature mismatch.\n");
    }

    printk(PFX "Received %d records.\n", hdr->records);
    // hex = to_hexstring(plain, outlen);
    // printk(PFX "Received plain: %s\n", hex);
    // kfree(hex);

    update_aes_key(hdr->key_update, sizeof(hdr->key_update));
}


void* generate_update(size_t *len) {

    void *update;
    struct trm_update_header *hdr;
    struct trm_update_record *rcrd;
    int num_records;
    int tmp;
    char *cipher; //, *hex;
    size_t outlen;
    int res;
    size_t required_space;
    
    num_records = 5;
    required_space = sizeof(struct trm_update_header) + num_records * sizeof(struct trm_update_record);

    update = kzalloc(required_space, GFP_KERNEL);
    if (!update) return NULL;

    hdr = (struct trm_update_header*)update;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    memset(hdr->key_update, 6, sizeof(hdr->key_update));
    hdr->records = (uint8_t)num_records;

    rcrd = (struct trm_update_record*)(update + sizeof(struct trm_update_header));
    for(tmp = 1; tmp < 2*num_records; tmp += 2) {
        memset(rcrd->subject, tmp, sizeof(rcrd->subject));
        memset(rcrd->data, tmp + 1, sizeof(rcrd->data));
        rcrd = (struct trm_update_record*)(rcrd + 1);
    }
    
    if (!registered) {
        printk(PFX "Can't generate update. Not registered.\n");
        *len = 0;
        return NULL;
    }

    cipher = kzalloc(required_space + TAG_LENGTH, GFP_KERNEL);
    outlen = required_space + TAG_LENGTH;
    res = trm_aes_encrypt(aes_key, update, required_space, cipher, &outlen);

    // hex = to_hexstring(cipher, outlen);
    // printk(PFX "Generated cipher: %s\n", hex);
    // kfree(hex);

    kfree(update);
    *len = outlen;
    return cipher;
}

// void update_requested(void);
// void update_received(void);
