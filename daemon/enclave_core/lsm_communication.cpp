
#include "includes/lsm_communication.h"

#ifndef __TRM_ENCLAVE_KEYS
#define __TRM_ENCLAVE_KEYS
#include "enclave_keys.h"
#endif

static unsigned char aes_key[16] = {"\0"};

sgx_status_t handle_kernel_challenge(uint8_t *challenge_data, size_t challenge_length, uint8_t *response_data, size_t response_length, int32_t pid)
{
    sgx_status_t status = SGX_SUCCESS;

    // ocall_print("-- Challenge read");
    // print_hex(challenge_data, challenge_length);
    unsigned char decrypted[RSA_BLOCK_SIZE];
    struct trm_challenge *challenge;
    size_t decrypted_len = RSA_BLOCK_SIZE;
    int result;

    // print_hex((unsigned char *)challenge_data, challenge_length);
    int err = rsa_decrypt(challenge_data, challenge_length, decrypted, &decrypted_len, &result, enclave_key_priv, enclave_key_priv_len);
    if (err != 0)
        return (sgx_status_t)err;
    // print_hex(decrypted, decrypted_len);

    // Check if its a trm_challenge.
    if (decrypted_len != sizeof(trm_challenge))
    {
        enclave_perror("Size of decrypted payload wrong.");
        return (sgx_status_t)decrypted_len;
    }

    challenge = (struct trm_challenge *)decrypted;
    if (memcmp(challenge->signature, challenge_signature, sizeof(challenge_signature)))
    {
        enclave_perror("Signatures don't match...");
        return (sgx_status_t)-5;
    }

    // Got a valid decrypted challenge.
    char name[] = "citadel.basic.so";
    memcpy(challenge->name, name, sizeof(name));
    sgx_read_rand(aes_key, 16);
    memcpy(challenge->key, aes_key, sizeof(aes_key));
    set_ptoken_aes_key(aes_key);
    challenge->pid = pid;

    // ocall_print("-- Response write");
    // print_hex((unsigned char*)challenge, sizeof(trm_challenge));
    unsigned char cipher[RSA_BLOCK_SIZE];
    size_t outlen = RSA_BLOCK_SIZE;
    err = rsa_encrypt((unsigned char *)challenge, sizeof(trm_challenge), cipher, &outlen, lsm_key_padded_pub, lsm_key_padded_pub_len);
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

void generate_ticket(int num_records)
{
    // Build ticket structure.

    char data[sizeof(trm_update_header) + num_records * sizeof(trm_update_record)];
    struct trm_update_header *hdr;
    struct trm_update_record *rcrd;

    hdr = (struct trm_update_header *)data;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    sgx_read_rand(hdr->key_update, sizeof(hdr->key_update));
    hdr->records = (uint8_t)num_records;

    rcrd = (struct trm_update_record *)(data + sizeof(struct trm_update_header));
    for (int tmp = 1; tmp < 2 * num_records; tmp += 2)
    {
        memset(rcrd->subject, tmp, sizeof(rcrd->subject));
        memset(rcrd->data, tmp + 1, sizeof(rcrd->data));
        rcrd = (struct trm_update_record *)(rcrd + 1);
    }

    // Encrypt.
    unsigned char cipher[sizeof(data) + 16];
    // memset(cipher, 0, 4096+16);
    size_t outlen = sizeof(data) + 16;
    int ret = aes_encrypt((unsigned char *)data, sizeof(data), cipher, &outlen, aes_key, sizeof(aes_key));
    // print_hex(cipher, outlen);

    // // Install.
    int install_ret;
    install_ticket(&install_ret, (uint8_t *)cipher, outlen);

    // TODO if successful
    update_aes_key(hdr->key_update, sizeof(hdr->key_update));
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

    struct trm_update_header *hdr;
    struct trm_update_record *rcrd;
    hdr = (struct trm_update_header *)plain;

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

bool generate_xattr_ticket(const char *path)
{
    char data[sizeof(trm_update_header) + sizeof(trm_update_record)];
    struct trm_update_header *hdr;
    struct trm_update_record *rcrd;

    hdr = (struct trm_update_header *)data;
    memcpy(hdr->signature, challenge_signature, sizeof(challenge_signature));
    sgx_read_rand(hdr->key_update, sizeof(hdr->key_update));
    hdr->records = (uint8_t)1;

    rcrd = (struct trm_update_record *)(data + sizeof(struct trm_update_header));
    sgx_read_rand(rcrd->subject, sizeof(rcrd->subject));
    memset(rcrd->data, 2, sizeof(rcrd->data));

    // print_hex((unsigned char*)rcrd->subject, sizeof(rcrd->subject));
    // print_hex((unsigned char*)data, sizeof(data));

    // Encrypt.
    unsigned char cipher[sizeof(data) + 16];
    size_t outlen = sizeof(data) + 16;
    int ret = aes_encrypt((unsigned char *)data, sizeof(data), cipher, &outlen, aes_key, sizeof(aes_key));

    int install_ret;
    size_t pathname_len = strlen(path) + 1;
    install_xattr(&install_ret, (char*)path, pathname_len, (uint8_t*)cipher, outlen);

    if (install_ret == XATTR_ACCEPTED_SIGNAL)
    {
        update_aes_key(hdr->key_update, sizeof(hdr->key_update));
        return true;
    }

    return false;
}