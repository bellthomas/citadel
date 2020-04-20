
#include <tomcrypt.h>
#include "crypto.h"

int rsa_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, int *result, unsigned char *key, unsigned int keylen) {
    ltc_mp = gmp_desc;
    rsa_key pkey_decrypt;
    int err = 0;

	err = rsa_import(key, keylen, &pkey_decrypt);
	if (err != CRYPT_OK) {
        ocall_print(error_to_string(err));
        rsa_free(&pkey_decrypt);
        return err;
    } 
    // else {
    //    ocall_print("Public key loaded.");
    // }

    // Register hash algorithm.
	const ltc_hash_descriptor& hash_desc = sha1_desc;
	const int hash_idx = register_hash(&hash_desc);
	if (hash_idx < 0) {
        err = -7;
        rsa_free(&pkey_decrypt);
        return err;
    };

	// Define padding scheme.
	const int padding = LTC_PKCS_1_V1_5; // LTC_PKCS_1_OAEP; //LTC_PKCS_1_V1_5;
	const unsigned long saltlen = 0;

    // Register PRNG algorithm.
    const int prng_idx = register_prng(&sprng_desc);
    if (prng_idx < 0) {
        err = -6;
        rsa_free(&pkey_decrypt);
        return err;
    };


    err = rsa_decrypt_key_ex(msg, len, out, outlen, NULL, 0, hash_idx, padding, result, &pkey_decrypt);
    if (err != CRYPT_OK) {
        ocall_print(error_to_string(err));
    }

free:
    rsa_free(&pkey_decrypt);
    return err;
}
