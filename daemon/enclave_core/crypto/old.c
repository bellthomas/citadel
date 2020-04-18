#include "Enclave_t.h"
#include "asm/interface.h"

// #define GMP_DESC
#define MAX_RSA_SIZE 4096 // bits
#include <tomcrypt.h>
// #include "enclave_keys.h"
#include <stdio.h>
#include <sgx_trts.h>

static unsigned char hex_buffer[4096] = {'\0'};
static unsigned char mem[1024000] = {'\0'};

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
    size_t  i;
    for (i = 0; i < sizeof(hex_buffer); i++) 
        hex_buffer[i] = '\0';
}

void print_hex(unsigned char *buf, unsigned int len) {
    load_hex_buffer(buf, len);
    ocall_print((const char*)hex_buffer);
}

int rsa_test() {
   ltc_mp = gmp_desc;

   const char msg[] = "This is a test";
   rsa_key key_pub, key_priv;

	int err = rsa_import(enclave_key_padded_pub, enclave_key_padded_pub_len, &key_pub);
	if (err != CRYPT_OK) {
        ocall_print(error_to_string(err));
        return err;
    } else {
       ocall_print("Public key loaded.");
    }

   err = rsa_import(enclave_key_priv, enclave_key_priv_len, &key_priv);
	if (err != CRYPT_OK) {
        ocall_print(error_to_string(err));
        return err;
    } else {
       ocall_print("Private key loaded.");
    }

    // Register hash algorithm.
	const ltc_hash_descriptor& hash_desc = sha512_desc;
	const int hash_idx = register_hash(&hash_desc);
	if (hash_idx < 0) return -1;

	// Hash message.
	unsigned char hash[64];
	hash_state md;
	hash_desc.init(&md);
	hash_desc.process(&md, (const unsigned char*)msg, (unsigned long)strlen(msg));
	hash_desc.done(&md, hash);
   ocall_print((const char*)hash);

	// Define padding scheme.
	const int padding = LTC_PKCS_1_V1_5;
	const unsigned long saltlen = 0;


   // unsigned char rnd_buf[2048];
   // sgx_status_t rnd = sgx_read_rand((uint8_t*)rnd_buf, (size_t)2048);
   // print_hex((unsigned char *)rnd_buf, (size_t)2048);

	// Register PRNG algorithm (PSS only).
	// const int prng_idx = padding == LTC_PKCS_1_PSS ? register_prng(&rc4_desc) : 0;
   const int prng_idx = register_prng(&sprng_desc);
	if (prng_idx < 0) return -6;

	// // Sign hash.
	// unsigned char sig[MAX_RSA_SIZE / 8];
	// unsigned long siglen = sizeof(sig);

   const unsigned char message[] = "This is the message to encrypt";
   unsigned char outmsg[2048/8];
   long unsigned int outlen = 2048/8;

	// // err = rsa_sign_hash_ex(hash, hash_desc.hashsize, sig, &siglen, padding, NULL, prng_idx, hash_idx, saltlen, &key);
   err = rsa_encrypt_key(message, sizeof(message), outmsg, &outlen, NULL, 0, NULL, prng_idx, hash_idx, &key_pub);
	if (err != CRYPT_OK) {
      ocall_print(error_to_string(err));
      return err;
   }
   print_hex(outmsg, 2048/8);
	// rsa_free(&key);

   unsigned char decrypted[2048/8];
   long unsigned int decrypted_len = 2048/8;
   int result;

   err = rsa_decrypt_key(outmsg, outlen, decrypted, &decrypted_len, NULL, 0, hash_idx, &result, &key_priv);
	if (err != CRYPT_OK) {
      ocall_print(error_to_string(err));
      return err;
   }
   print_hex(decrypted, 2048/8);


   // int encrypt_err = rsa_encrypt_key(message, sizeof(message), outmsg, &outlen, NULL, 0, NULL, prng_idx, hash_idx, &key);
   // if (encrypt_err != CRYPT_OK) {
   //      ocall_print(error_to_string(encrypt_err));
   //      return encrypt_err;
   //  } else {
   //     ocall_print("yes!");
   //  }
   // print_hex(outmsg, 2048);

   rsa_free(&key_pub);
    return 0;
}


int generate_random_number() {
    ocall_print("Processing random number generation...");
    return rsa_test();
}