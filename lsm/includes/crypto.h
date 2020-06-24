
#ifndef _SECURITY_TRM_CRYPTO_H
#define _SECURITY_TRM_CRYPTO_H

#define AES_ENCRYPT 1
#define AES_DECRYPT 2

extern int trm_rsa_self_test(void);
extern char* trm_rsa_encrypt(char* data, size_t data_len, int* return_size);
extern char* trm_rsa_decrypt(char* data, size_t data_len, int* return_size);

extern int trm_aes_self_test(void);
extern int trm_aes_decrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen);
extern int trm_aes_encrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen);


#endif  /* _SECURITY_TRM_CRYPTO_H */