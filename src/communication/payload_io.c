#include "../../includes/payload_io.h"

static unsigned char current_challenge[_TRM_CHALLENGE_LENGTH];
static char registered_name[_TRM_NAME_LENGTH];
static char aes_key[_TRM_AES_KEY_LENGTH];
static char ptoken_aes_key[_TRM_AES_KEY_LENGTH];
static int registered = 0;
static int32_t enclave_pid = 0;

int system_ready() {
    return registered;
}

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
    if (decrypted_len == 0 || !challenge) {
        printk(PFX "Rejected challenge response: decryption failed.\n");
        goto bail;
    }
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
    memcpy(ptoken_aes_key, challenge->key, sizeof(aes_key));
    enclave_pid = challenge->pid;

    printk(PFX "Successfully registered with %s (%d)\n", registered_name, enclave_pid);
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
    size_t outlen, iter;
    bool success = true;
    int res;
    struct trm_update_header *hdr;
    citadel_update_record_t *rcrd;

    if (!registered) {
        printk(PFX "Can't process update. Not registered.\n");
        return;
    }

    if (update_len <= IV_LENGTH + TAG_LENGTH) {
        printk(PFX "Invalid payload. Too short (%ld)\n", update_len);
        return;
    }
    
    plain = kzalloc(update_len, GFP_KERNEL);
    outlen = update_len;
    res = trm_aes_decrypt(aes_key, update, update_len, plain, &outlen);

    // TODO make more robust.

    hdr = (struct trm_update_header*)plain;
    if(memcmp(hdr->signature, challenge_signature, sizeof(challenge_signature))) {
        printk(PFX "Rejected updates. Signature mismatch.\n");
    }

    printk(PFX "Received %d records.\n", hdr->records);
    rcrd = (citadel_update_record_t *)(plain + sizeof(struct trm_update_header));
    for (iter = 0; iter < hdr->records; iter++) {
        // success = insert_ticket(rcrd);
        // if (!success) printk(PFX "Failed to install a ticket for PID %d\n", current->pid);
        rcrd = (citadel_update_record_t *)(rcrd + 1);
    }

    update_aes_key(hdr->key_update, sizeof(hdr->key_update));
    kfree(plain);
}


void* generate_update(size_t *len) {

    void *update;
    struct trm_update_header *hdr;
    citadel_update_record_t *rcrd;
    int num_records;
    int tmp;
    char *cipher; //, *hex;
    size_t outlen;
    int res;
    size_t required_space;
    
    num_records = 5;
    required_space = sizeof(struct trm_update_header) + num_records * sizeof(citadel_update_record_t);

    update = kzalloc(required_space, GFP_KERNEL);
    if (!update) return NULL;

    hdr = (struct trm_update_header*)update;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    memset(hdr->key_update, 6, sizeof(hdr->key_update));
    hdr->records = (uint8_t)num_records;

    rcrd = (citadel_update_record_t *)(update + sizeof(struct trm_update_header));
    for(tmp = 1; tmp < 2*num_records; tmp += 2) {
        rcrd->pid = 13;
        rcrd->operation = 0;
        memset(rcrd->identifier, tmp, sizeof(rcrd->identifier));
        rcrd = (citadel_update_record_t *)(rcrd + 1);
    }
    
    if (!registered) {
        printk(PFX "Can't generate update. Not registered.\n");
        *len = 0;
        return NULL;
    }

    // TODO verify size
    cipher = kzalloc(required_space + TAG_LENGTH + IV_LENGTH, GFP_KERNEL);
    outlen = required_space + TAG_LENGTH + IV_LENGTH;
    res = trm_aes_encrypt(aes_key, update, required_space, cipher, &outlen);

    // hex = to_hexstring(cipher, outlen);
    // printk(PFX "Generated cipher: %s\n", hex);
    // kfree(hex);

    kfree(update);
    *len = outlen;
    return cipher;
}

int xattr_enclave_installation(const void *value, size_t size, struct dentry *dentry) {
    char *plain, *identifier_hex;
    size_t outlen;
    int res, xattr_success;
    struct trm_update_header *hdr;
    citadel_update_record_t *rcrd;
    citadel_inode_data_t *d_inode_data = trm_inode(dentry->d_inode);

    if (!registered) {
        printk(PFX_W "Can't process update. Not registered.\n");
        return -1;
    }

    if (size <= IV_LENGTH + TAG_LENGTH) {
        printk(PFX_W "Invalid payload. Too short (%ld)\n", size);
        return -1;
    }
    
    plain = kzalloc(size, GFP_KERNEL);
    outlen = size;

    res = trm_aes_decrypt(aes_key, (void*)value, size, plain, &outlen);
    if (res) {
        printk(PFX_W "Rejected updates. Decryption failed.\n");
        return -1;
    }

    hdr = (struct trm_update_header*)plain;
    if(memcmp(hdr->signature, challenge_signature, sizeof(challenge_signature))) {
        printk(PFX_W "Rejected updates. Signature mismatch.\n");
        return -1;
    }

    // Only expecting a single record.
    if (hdr->records != 1) return -1;
    rcrd = (citadel_update_record_t *)(plain + sizeof(struct trm_update_header));

    // Set the xattr values.
    identifier_hex = to_hexstring(rcrd->identifier, _TRM_IDENTIFIER_LENGTH);
    // need to lock inode->i_rwsem
    // down_write(&(dentry->d_inode->i_rwsem));
    xattr_success = __vfs_setxattr_noperm(dentry, TRM_XATTR_ID_NAME, (const void*)identifier_hex, _TRM_IDENTIFIER_LENGTH * 2, 0);
    __vfs_setxattr_noperm(dentry, TRM_XATTR_REALM_NAME, NULL, 0, 0);
	// up_write(&(dentry->d_inode->i_rwsem));
    kfree(identifier_hex);

    if(xattr_success == 0) {
        // Update internal kernel structure.
        d_inode_data->in_realm = true;
        d_inode_data->needs_xattr_update = false;
        d_inode_data->checked_disk_xattr = true;
        memcpy(d_inode_data->identifier, rcrd->identifier, sizeof(d_inode_data->identifier));

        update_aes_key(hdr->key_update, sizeof(hdr->key_update));
        kfree(plain);
        return 0;
    } else {
        kfree(plain);
        return -1;
    }
}


void* generate_ptoken(size_t *len) {
    char *cipher, *hex;
    size_t outlen;
    int res, required_size;
    struct trm_ptoken_protected to_encrypt;
    struct trm_ptoken *signed_ptoken;

    if (!system_ready()) {
        printk(PFX_W "Can't provide ptoken. Not registered.\n");
        return NULL;
    }

    signed_ptoken = kzalloc(sizeof(struct trm_ptoken), GFP_KERNEL);
    memcpy(signed_ptoken->signature, challenge_signature, sizeof(challenge_signature));
    get_random_bytes(signed_ptoken->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
    signed_ptoken->citadel_pid = (int32_t)enclave_pid;

    // Generate cipher payload.
    memcpy(to_encrypt.signature, challenge_signature, sizeof(challenge_signature));
    to_encrypt.pid = (int32_t)current->pid;
    memcpy(to_encrypt.ptoken, signed_ptoken->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);

    required_size = sizeof(struct trm_ptoken_protected) + TAG_LENGTH + IV_LENGTH;
    cipher = kzalloc(required_size, GFP_KERNEL);
    outlen = required_size;
    res = trm_aes_encrypt(ptoken_aes_key, &to_encrypt, sizeof(struct trm_ptoken_protected), cipher, &outlen);
    if (res) {
        kfree(cipher);
        *len = 0;
        return NULL;
    }

    memcpy(signed_ptoken->signed_ptoken, cipher, outlen);
    kfree(cipher);

    hex = to_hexstring(signed_ptoken->ptoken, _TRM_PROCESS_PTOKEN_LENGTH);
    printk(PFX "Generated ptoken for PID %d: %s\n", current->pid, hex);
    kfree(hex);

    *len = sizeof(struct trm_ptoken);
    return signed_ptoken;
}