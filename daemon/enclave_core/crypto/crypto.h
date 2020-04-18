

#ifndef TRM_CRYPTO_H_
#define TRM_CRYPTO_H_

#include "Enclave_t.h"
#include "asm/interface.h"

// #define GMP_DESC
#define MAX_RSA_SIZE 4096 // bits
#include <tomcrypt.h>


#include <stdio.h>
#include <sgx_trts.h>

extern int rsa_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, int *result, unsigned char *key, unsigned int keylen);
extern int rsa_encrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen);
extern int aes_encrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen);
extern int aes_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen);

#endif