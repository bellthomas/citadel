#include "crypto.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <string.h>

#define BUFLEN 2048

void decryptMessage(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut, uint8_t *key) {
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t*)key,
		encMessage,
		lenOut,
		p_dst,
		encMessage + (len - SGX_AESGCM_IV_SIZE),
		SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (encMessage + (len - SGX_AESGCM_IV_SIZE - SGX_AESGCM_MAC_SIZE))
	);

	memcpy(decMessageOut, p_dst, lenOut);
}

void encryptMessage(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut, uint8_t *key) {
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = { 0 };
	sgx_read_rand(p_dst + len + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		(sgx_aes_gcm_128bit_key_t*)key,
		origMessage,
		len, 
		p_dst, // + SGX_AESGCM_IV_SIZE, // p_dst
		p_dst + len + SGX_AESGCM_MAC_SIZE,
		SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst + len)
	);	

	memcpy(encMessageOut, p_dst, lenOut);
}

int aes_encrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen) {
    size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + len);
    encryptMessage((char*)msg, len, (char*)out, encMessageLen, (uint8_t*)key);
    *outlen = encMessageLen;
    return 0;
}


int aes_decrypt(unsigned char *msg, size_t len, unsigned char *out, size_t *outlen, unsigned char *key, unsigned int keylen) {
    size_t decMessageLen = len - (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE);
    decryptMessage((char*) msg, len, (char*)out, decMessageLen, (uint8_t*)key);
    *outlen = decMessageLen;
    return 0;
}
