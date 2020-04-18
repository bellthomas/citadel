#include "includes/crypto.h"
#include "lsm_keys.h"
// #include "enclave_keys.h"


#define RSA_ENCRYPT  0
#define RSA_DECRYPT  1
#define RSA_PUB_KEY  2
#define RSA_PRIV_KEY 3



struct tcrypt_result {
    struct completion completion;
    int err;
};


void tcrypt_complete(struct crypto_async_request *req, int err) {
    struct tcrypt_result *res = req->data;
    printk(KERN_INFO "LSM/TRM: tcrypt_complete -> %d\n", err);
    if (err == -EINPROGRESS)
        return;

    res->err = err;
    complete(&res->completion);
}

int wait_async_op(struct tcrypt_result *tr, int ret) {
    if (ret == -EINPROGRESS || ret == -EBUSY) {
        wait_for_completion(&tr->completion);
        reinit_completion(&tr->completion);
        ret = tr->err;
    }
    return ret;
}

int uf_akcrypto(struct crypto_akcipher *tfm, void *data, int datalen, struct akcipher_request *req, int mode, void* res, int* res_len) {
    void *xbuf = NULL;
    void *outbuf = NULL;
    struct tcrypt_result result;
    unsigned int out_len_max = 0;
    struct scatterlist src, dst;

    int err = -ENOMEM;
    xbuf = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (!xbuf) return err;

    init_completion(&result.completion);

    err = -ENOMEM;
    out_len_max = crypto_akcipher_maxsize(tfm);
    // printk(KERN_INFO "LSM/TRM: crypto_akcipher_maxsize -> %d\n", out_len_max);

    outbuf = kzalloc(out_len_max, GFP_KERNEL);
    // printk(KERN_INFO "LSM/TRM: crypto_akcipher_maxsize kzalloc -> %p\n", outbuf);

    if (!outbuf) goto free_xbuf;
    if (WARN_ON(datalen > PAGE_SIZE)) goto free_all;

    memcpy(xbuf, data, datalen);
    sg_init_one(&src, xbuf, datalen);
    sg_init_one(&dst, outbuf, out_len_max);
    akcipher_request_set_crypt(req, &src, &dst, datalen, out_len_max);
    akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG | CRYPTO_TFM_REQ_MAY_SLEEP, tcrypt_complete, &result);

    if (mode == RSA_ENCRYPT) {
        err = wait_async_op(&result, crypto_akcipher_encrypt(req));
        if (err) {
            pr_err("LSM/TRM: Encryption failed -- err %d\n", err);
            goto free_all;
        }

    } else if (mode == RSA_DECRYPT) {
        err = wait_async_op(&result, crypto_akcipher_decrypt(req));
        if (err) {
            pr_err("LSM/TRM: Decryption failed -- err %d\n", err);
            goto free_all;
        }
        
    } else {
        printk(KERN_INFO "LSM/TRM: Invalid mode (%d)\n", mode);
    }

    // Copy result out.
    // TODO: check for failure.
    memcpy(res, outbuf, out_len_max);
    *res_len = out_len_max;

free_all:
    kfree(outbuf);
free_xbuf:
    kfree(xbuf);
    return err;
}



int trm_akcrypto(char* key, int key_len, void *data, int data_len, int mode, int keytype, void* res, int* res_len) {
    struct crypto_akcipher *tfm;
    struct akcipher_request *req;
    int err, key_err;

    // Create RSA object.
    tfm = crypto_alloc_akcipher("rsa", CRYPTO_ALG_INTERNAL, 0);
    if (IS_ERR(tfm)) {
        pr_err("LSM/TRM: akcipher: Failed to load tfm for rsa: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    // Set the RSA key.
    if (keytype == RSA_PUB_KEY)
        key_err = crypto_akcipher_set_pub_key(tfm, key, key_len);
    else if (keytype == RSA_PRIV_KEY)
        key_err = crypto_akcipher_set_priv_key(tfm, key, key_len);
    else {
        pr_err("LSM/TRM: Invalid keytype (%d).\n", keytype);
        err = -100;
        goto free_cipher;
    }

    // Initialise cipher request and call function.
    req = akcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("LSM/TRM: Failed to allocate ak_cipher_request.\n");
        err = -101;
        goto free_cipher;
    }

    err = uf_akcrypto(tfm, data, data_len, req, mode, res, res_len);
    if (err) {
        printk(KERN_INFO "LSM/TRM: uf_akcrypto fail, err=%d\n", err);
    }

    akcipher_request_free(req);
free_cipher:
    crypto_free_akcipher(tfm);

    return err;
}


int trm_akcrypto_encrypt_pub(void *data, int datalen, void* res, int* res_len) {
    return trm_akcrypto(enclave_key_pub, enclave_key_pub_len, data, datalen, RSA_ENCRYPT, RSA_PUB_KEY, res, res_len);
}

// Evil.
int trm_akcrypto_decrypt_pub(void *data, int datalen, void* res, int* res_len) {
    return trm_akcrypto(lsm_key_pub, lsm_key_pub_len, data, datalen, RSA_DECRYPT, RSA_PUB_KEY, res, res_len);
}

int trm_akcrypto_encrypt_priv(void *data, int datalen, void* res, int* res_len) {
    return trm_akcrypto(lsm_key_priv, lsm_key_priv_len, data, datalen, RSA_ENCRYPT, RSA_PRIV_KEY, res, res_len);
}

int trm_akcrypto_decrypt_priv(void *data, int datalen, void* res, int* res_len) {
    return trm_akcrypto(lsm_key_priv, lsm_key_priv_len, data, datalen, RSA_DECRYPT, RSA_PRIV_KEY, res, res_len);
}

// ------------------------------------------------

char* trm_rsa_encrypt(char* data, size_t data_len, int* return_size) {
    void *cipher_page, *cipher;
    int res;

    cipher_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (cipher_page) {
        res = trm_akcrypto_encrypt_pub((void*)data, data_len, cipher_page, return_size);
        if(res) {
            printk(KERN_INFO "LSM/TRM: Failed to encrypt data (err %d)\n", res);
            kfree(cipher_page);
            goto fail;
        }

        cipher = kzalloc(*return_size, GFP_KERNEL);
        memcpy(cipher, cipher_page, *return_size);
        kfree(cipher_page);
        return cipher;
    }

fail:
    *return_size = 0;
    return NULL;
}

char* trm_rsa_decrypt(char* data, size_t data_len, int* return_size) {
    void *plain_page, *plain;
    int res;

    plain_page = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (plain_page) {
        res = trm_akcrypto_decrypt_priv((void*)data, data_len, plain_page, return_size);
        if(res) {
            printk(KERN_INFO "LSM/TRM: Failed to decrypt data (err %d)\n", res);
            kfree(plain_page);
            goto fail;
        }

        plain = kzalloc(*return_size, GFP_KERNEL);
        memcpy(plain, plain_page, *return_size);
        kfree(plain_page);
        return plain;
    }

fail:
    *return_size = 0;
    return NULL;
}

int trm_rsa_self_test(void) {   
    int res;
    void *cipher, *result;
    char *hexmsg, *hexmsg2;
    int cipher_len, result_len;
    const char* msg = "ABCDEFGH";
    const int msg_len = 8;

    // Encrypt with public key.
    printk(KERN_INFO "LSM/TRM: RSA test -- stage 1.\n");
    cipher = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (cipher) {
        res = trm_akcrypto_encrypt_pub((void*)msg, msg_len, cipher, &cipher_len);
        if(!res) {
            hexmsg = to_hexstring(cipher, cipher_len);
            printk(KERN_INFO "LSM/TRM: Encrypted using public key: (%d bytes) %s\n", cipher_len, hexmsg);
            kfree(hexmsg);
        } else {
            printk(KERN_INFO "LSM/TRM: [FAIL] Encrypted using public key: %d\n", res);
        }
    } else {
        printk(KERN_INFO "LSM/TRM: [FAIL] Couldn't allocate page for result.\n");
        goto bail;
    }

    // Test decrypt using private key.
    printk(KERN_INFO "LSM/TRM: RSA test -- stage 2.\n");
    result = kzalloc(PAGE_SIZE, GFP_KERNEL);
    if (result) {
        res = trm_akcrypto_decrypt_priv((void*)cipher, cipher_len, result, &result_len);
        if(!res) {
            hexmsg2 = to_hexstring(result, result_len);
            printk(KERN_INFO "LSM/TRM: Decrypted using private key: (%d bytes) %s\n", result_len, hexmsg2);
            kfree(hexmsg2);
        } else {
            printk(KERN_INFO "LSM/TRM: [FAIL] Decrypted using private key: %d\n", res);
        }
        kfree(result);
        kfree(cipher);
    } else {
        printk(KERN_INFO "LSM/TRM: [FAIL] Couldn't allocate page for result.\n");
        kfree(cipher);
        goto bail;
    }
    
    cipher_len = 0;
    result_len = 0;

bail:
    return 0;
}
