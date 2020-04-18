
#include <tomcrypt.h>
#include "crypto.h"

int rsa_encrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen) {
    ltc_mp = gmp_desc;
    rsa_key pkey_encrypt;
    int err = 0;

    err = rsa_import(key, keylen, &pkey_encrypt);
    if (err != CRYPT_OK) {
        ocall_print("a");
        ocall_print(error_to_string(err));
        rsa_free(&pkey_encrypt);
        return err;
    } else {
        ocall_print("Private key loaded.");
    }

    // Register hash algorithm.
	const ltc_hash_descriptor& hash_desc = sha256_desc;
	const int hash_idx = register_hash(&hash_desc);
	if (hash_idx < 0) {
        err = -9;
        rsa_free(&pkey_encrypt);
        return err;
    };
    
	// Register PRNG algorithm.
    const int prng_idx = register_prng(&sprng_desc);
    if (prng_idx < 0) {
        err = -8;
        rsa_free(&pkey_encrypt);
        return err;
    }

    err = rsa_encrypt_key(msg, len, out, outlen, NULL, 0, NULL, prng_idx, hash_idx, &pkey_encrypt);
    if (err != CRYPT_OK) {
        ocall_print("b");
        ocall_print(error_to_string(err));
    }

    rsa_free(&pkey_encrypt);
    return err;
}