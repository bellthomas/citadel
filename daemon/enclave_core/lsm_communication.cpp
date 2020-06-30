
#include "includes/lsm_communication.h"

static bool keys_loaded = false;
static unsigned char aes_key[_CITADEL_AES_KEY_LENGTH] = {"\0"};
static unsigned char enclave_key_priv[_CITADEL_KEY_PRIV_LEN] = {"\0"};
static unsigned char enclave_key_padded_pub[_CITADEL_KEY_PUB_PAD_LEN] = {"\0"};
static unsigned char enclave_key_pub[_CITADEL_KEY_PUB_LEN] = {"\0"};
static unsigned char lsm_key_padded_pub[_CITADEL_KEY_PUB_PAD_LEN] = {"\0"};
static unsigned char lsm_key_pub[_CITADEL_KEY_PUB_LEN] = {"\0"};
static uint16_t enclave_key_priv_len = 0;

sgx_status_t handle_kernel_challenge(uint8_t *challenge_data, size_t challenge_length, uint8_t *response_data, size_t response_length, int32_t pid)
{
    sgx_status_t status = SGX_SUCCESS;

    // ocall_print("-- Challenge read");
    // print_hex(challenge_data, challenge_length);
    unsigned char decrypted[_CITADEL_RSA_KEY_LENGTH];
    citadel_challenge_t *challenge;
    size_t decrypted_len = _CITADEL_RSA_KEY_LENGTH;
    int result;

    // print_hex((unsigned char *)challenge_data, challenge_length);
    int err = rsa_decrypt(challenge_data, challenge_length, decrypted, &decrypted_len, &result, enclave_key_priv, enclave_key_priv_len);
    if (err != 0)
        return (sgx_status_t)err;
    // print_hex(decrypted, decrypted_len);

    // Check if its a citadel_challenge.
    if (decrypted_len != sizeof(citadel_challenge_t))
    {
        enclave_perror("Size of decrypted payload wrong.");
        return (sgx_status_t)decrypted_len;
    }

    challenge = (citadel_challenge_t *)decrypted;
    if (memcmp(challenge->signature, challenge_signature, sizeof(challenge_signature)))
    {
        enclave_perror("Signatures don't match...");
        return (sgx_status_t)-5;
    }

    // Got a valid decrypted challenge.
    char name[] = "citadel.basic.so";
    memcpy(challenge->name, name, sizeof(name));
    sgx_read_rand(aes_key, _CITADEL_AES_KEY_LENGTH);
    memcpy(challenge->key, aes_key, sizeof(aes_key));
    set_ptoken_aes_key(aes_key);
    challenge->pid = pid;

    // ocall_print("-- Response write");
    // print_hex((unsigned char*)challenge, sizeof(citadel_challenge_t));
    unsigned char cipher[_CITADEL_RSA_KEY_LENGTH];
    size_t outlen = _CITADEL_RSA_KEY_LENGTH;
    err = rsa_encrypt((unsigned char *)challenge, sizeof(citadel_challenge_t), cipher, &outlen, lsm_key_padded_pub, sizeof(lsm_key_padded_pub));
    if (err != 0)
        return (sgx_status_t)err;
    // print_hex(cipher, outlen);

    memcpy(response_data, cipher, response_length);

    return (sgx_status_t)0;
}

void update_aes_key(void *key, size_t key_len)
{
    if (key_len >= sizeof(aes_key))
    {
        for (int i = 0; i < sizeof(aes_key); i++)
        {
            aes_key[i] = aes_key[i] ^ ((unsigned char *)key)[i];
        }
    }
    // ocall_print("\n** Updated AES key.");
    // print_hex(aes_key, sizeof(aes_key));
    // ocall_print("**");
}

bool generate_ticket(int32_t pid, const char *metadata, citadel_operation_t operation)
{
    // Build ticket structure.

    char data[sizeof(citadel_update_header_t) + sizeof(citadel_update_record_t)];
    citadel_update_header_t *hdr;
    citadel_update_record_t *rcrd;

    // Build ticket header.
    hdr = (citadel_update_header_t *)data;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    sgx_read_rand(hdr->key_update, sizeof(hdr->key_update));
    hdr->records = (uint8_t) 1;

    // Set ticket bidy.
    rcrd = (citadel_update_record_t *)(data + sizeof(citadel_update_header_t));
    memcpy(rcrd->identifier, metadata, sizeof(rcrd->identifier));
    rcrd->pid = pid;
    rcrd->operation = operation;

    // Encrypt.
    unsigned char cipher[sizeof(data) + 16];
    size_t outlen = sizeof(data) + 16;
    int ret = aes_encrypt((unsigned char *)&data, sizeof(data), cipher, &outlen, aes_key, sizeof(aes_key));
    if (ret) {
        enclave_perror("Failed to encrypt ticket.");
        return false;
    }

    // // Install.
    int install_ret; // The number of bytes written.
    install_ticket(&install_ret, (uint8_t *)cipher, outlen);
    if (!install_ret) {
        enclave_perror("Failed to install ticket.");
        return false;
    }

    update_aes_key(hdr->key_update, sizeof(hdr->key_update));
    return true;
}


int process_updates(uint8_t *update_data, size_t update_length)
{
    // ocall_print("-\nProcessing updates.");
    // print_hex((unsigned char*)update_data, update_length);

    unsigned char plain[update_length];
    size_t outlen = update_length;
    int ret = aes_decrypt(update_data, update_length, plain, &outlen, aes_key, sizeof(aes_key));
    // print_hex((unsigned char*)plain, outlen);
    // ocall_print("\ndissecting records...");

    citadel_update_header_t *hdr;
    citadel_update_record_t *rcrd;
    hdr = (citadel_update_header_t *)plain;

    if (memcmp(hdr->signature, challenge_signature, sizeof(challenge_signature)))
    {
        enclave_perror("Rejected updates. Signature mismatch.");
        return -1;
    }

    // char msg[256];
    // int n = snprintf(msg, sizeof(msg), "Found %d records.\nKey update:", hdr->records);
    // ocall_print(msg);
    // print_hex(hdr->key_update, sizeof(hdr->key_update));

    return 0;
}


static bool _generate_xattr_ticket(const char* path, bool internal, char *identifier, bool taint, bool declassify)
{
    // The +11 is to mitigate a bug in the SGX runtime.
    // Hypothesis: an illegal insturction is called if the stack frame isn't word-aligned (16 bytes).
    char data[sizeof(citadel_update_header_t) + sizeof(citadel_update_record_t)];
    citadel_update_header_t *hdr;
    citadel_update_record_t *rcrd;

    hdr = (citadel_update_header_t *)data;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    sgx_read_rand(hdr->key_update, sizeof(hdr->key_update));
    hdr->records = (uint8_t)1;

    rcrd = (citadel_update_record_t *)(data + sizeof(citadel_update_header_t));
    rcrd->pid = 0;
    rcrd->operation = (declassify ? CITADEL_OP_DECLASSIFY : (taint ? CITADEL_OP_REGISTER : CITADEL_OP_NOP));
    if (internal && !declassify)
        memset(rcrd->identifier, 0xFF, sizeof(rcrd->identifier));
    else
        sgx_read_rand(rcrd->identifier, sizeof(rcrd->identifier));
        


    // Encrypt.
    unsigned char cipher[sizeof(data) + 16];
    size_t outlen = sizeof(data) + 16;
    int ret = aes_encrypt((unsigned char *)data, sizeof(data), cipher, &outlen, aes_key, sizeof(aes_key));

    int install_ret;
    size_t pathname_len = strlen(path) + 1;
    install_xattr(&install_ret, (char*)path, pathname_len, (uint8_t*)cipher, outlen);

    if (install_ret == _CITADEL_XATTR_ACCEPTED_SIGNAL)
    {
        update_aes_key(hdr->key_update, sizeof(hdr->key_update));
        if (identifier != NULL && !declassify)
            memcpy(identifier, rcrd->identifier, sizeof(rcrd->identifier));
        return true;
    }

    return false;
}

bool generate_xattr_ticket(const char *path, char *identifier, bool taint, bool declassify)
{
    return _generate_xattr_ticket(path, false, identifier, taint, declassify);
}

bool generate_xattr_ticket_internal(const char *path)
{
    return _generate_xattr_ticket(path, true, NULL, true, false);
}

sgx_status_t process_sealed_keys(uint8_t* data, size_t length) {
    uint32_t plaintext_len = _CITADEL_SEAL_MAXSIZE;
    char plaintext[_CITADEL_SEAL_MAXSIZE];
    uint32_t mac_len = (uint32_t)strlen(_CITADEL_SEAL_MAC);
    char mac[] = _CITADEL_SEAL_MAC;
    sgx_status_t status = sgx_unseal_data(
        (const sgx_sealed_data_t*)data,
        (uint8_t*)mac,
        &mac_len,
        (uint8_t*)plaintext,
        &plaintext_len
    );


    // Load keys.
    if (status == 0) {
        size_t offset = 0;
        memcpy((void*)&enclave_key_priv_len, plaintext, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        memcpy(enclave_key_priv, plaintext + offset, enclave_key_priv_len);
        offset += enclave_key_priv_len;
        memcpy(enclave_key_padded_pub, plaintext + offset, _CITADEL_KEY_PUB_PAD_LEN);
        offset += _CITADEL_KEY_PUB_PAD_LEN;
        memcpy(enclave_key_pub, plaintext + offset, _CITADEL_KEY_PUB_LEN);
        offset += _CITADEL_KEY_PUB_LEN;
        memcpy(lsm_key_padded_pub, plaintext + offset, _CITADEL_KEY_PUB_PAD_LEN);
        offset += _CITADEL_KEY_PUB_PAD_LEN;
        memcpy(lsm_key_pub, plaintext + offset, _CITADEL_KEY_PUB_LEN);
        offset += _CITADEL_KEY_PUB_LEN;

        keys_loaded = true;
    }

    return status;
}