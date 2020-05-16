
#ifndef _SECURITY_TRM_CRYPTO_H
#define _SECURITY_TRM_CRYPTO_H

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>
#include <linux/gfp.h>
#include <linux/err.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <crypto/aead.h>
#include <crypto/akcipher.h>
#include <linux/random.h>
#include <linux/delay.h>
#include <linux/highmem.h>

#include "trm.h"
#include "common.h"

#define RSA_PAYLOAD_SIZE 256

#define AES_ENCRYPT 1
#define AES_DECRYPT 2
#define AES_KEY_SIZE 16

extern int trm_rsa_self_test(void);
extern char* trm_rsa_encrypt(char* data, size_t data_len, int* return_size);
extern char* trm_rsa_decrypt(char* data, size_t data_len, int* return_size);

extern int trm_aes_self_test(void);
extern int trm_aes_decrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen);
extern int trm_aes_encrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen);


#endif  /* _SECURITY_TRM_CRYPTO_H */