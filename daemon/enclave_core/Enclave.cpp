
#include "includes/enclave.h"

// Hex printing facility.
static unsigned char hex_buffer[4096] = {'\0'};

void load_hex_buffer(unsigned char *buf, unsigned int len) {
    size_t  i;
    if (buf == NULL || len == 0) return;
    for (i=0; i<len; i++) {
        hex_buffer[i*2]   = "0123456789ABCDEF"[buf[i] >> 4];
        hex_buffer[i*2+1] = "0123456789ABCDEF"[buf[i] & 0x0F];
    }
    hex_buffer[len*2] = '\0';
}

void reset_hex_buffer() {
    size_t i;
    for (i = 0; i < sizeof(hex_buffer); i++) 
        hex_buffer[i] = '\0';
}

void print_hex(unsigned char *buf, unsigned int len) {
    load_hex_buffer(buf, len);
    ocall_print((const char*)hex_buffer);
}

void timer_pulse(void) {
    ocall_print("Timer...");
    generate_ticket(9);
    generate_ticket(8);
    generate_ticket(7);
    generate_ticket(6);
    generate_ticket(5);
    generate_ticket(4);
    generate_ticket(3);
    generate_ticket(2);
    generate_ticket(1);
    generate_ticket(9);
}

//
int generate_random_number() {
    ocall_print("Processing random number generation...");

    // unsigned char msg[] = "This is my secret message";
    // unsigned char cipher[2048];
    // size_t outlen;
    // int err = rsa_encrypt(msg, sizeof(msg), cipher, &outlen, enclave_key_padded_pub, enclave_key_padded_pub_len);
    // print_hex(cipher, outlen);

    // unsigned char decrypted[2048];
    // size_t decrypted_len;
    // int result;
    // err = rsa_decrypt(cipher, outlen, decrypted, &decrypted_len, &result, enclave_key_priv, enclave_key_priv_len);

    // // unsigned char decrypted[2048];
    // // size_t decrypted_len;
    // // int result;
    // // err = rsa_decrypt(cipher, 2048/8, decrypted, &decrypted_len, &result, enclave_key_priv, enclave_key_priv_len);
    // ocall_print((const char*)decrypted);

    // sgx_aes_gcm_128bit_key_t key = { 0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };
    // unsigned char aes_msg[] = "This is my secret message 2";
    // unsigned char aes_cipher[2048];
    // size_t aes_cipher_len;
    // err = aes_encrypt(aes_msg, sizeof(aes_msg), aes_cipher, &aes_cipher_len, key, sizeof(key));
    // print_hex(aes_cipher, aes_cipher_len);

    // unsigned char aes_plain[2048];
    // size_t aes_plain_len;
    // err = aes_decrypt(aes_cipher, aes_cipher_len, aes_plain, &aes_plain_len, key, sizeof(key));
    // print_hex(aes_plain, aes_plain_len);
    // ocall_print((const char*)aes_plain);

    return 0;
}

