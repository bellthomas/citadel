#include "includes/crypto.h"

#define AES_ENCRYPT 1
#define AES_DECRYPT 2
#define AES_KEY_SIZE 64


static int trm_aes_operation(struct crypto_skcipher *tfm, struct skcipher_request *req, 
                             u8 *key, size_t key_size, void *data, size_t datasize, int mode) {
    // u8 *data = NULL;
    // const size_t datasize = 512; /* data size in bytes */
    struct scatterlist sg;
    DECLARE_CRYPTO_WAIT(wait);
    u8 iv[16];  /* AES-256-XTS takes a 16-byte IV */
    int err;

    err = crypto_skcipher_setkey(tfm, key, key_size);
    if (err) {
        pr_err("Error setting key: %d\n", err);
        goto out;
    }

    /* Initialize the IV */
    memset(iv, 0, sizeof(iv));
    // get_random_bytes(iv, sizeof(iv));

    /*
     * Encrypt the data in-place.
     *
     * For simplicity, in this example we wait for the request to complete
     * before proceeding, even if the underlying implementation is asynchronous.
     *
     * To decrypt instead of encrypt, just change crypto_skcipher_encrypt() to
     * crypto_skcipher_decrypt().
     */
    sg_init_one(&sg, data, datasize);
    skcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, crypto_req_done, &wait);
    skcipher_request_set_crypt(req, &sg, &sg, datasize, iv);

    if (mode == AES_ENCRYPT) err = crypto_wait_req(crypto_skcipher_encrypt(req), &wait);
    else err = crypto_wait_req(crypto_skcipher_decrypt(req), &wait);
    if (err) {
        pr_err(PFX "AES processing error: %d\n", err);
        goto out;
    }

out:
    return err;
}

void random_bytes(uint8_t *key, size_t key_len) {
    get_random_bytes(key, key_len);
}

int prepare_skcipher(uint8_t *key, void *data, size_t datasize, int mode) {
    struct crypto_skcipher *tfm = NULL;
    struct skcipher_request *req = NULL;
    int res;

    /*
    * Allocate a tfm (a transformation object) and set the key.
    *
    * In real-world use, a tfm and key are typically used for many
    * encryption/decryption operations.  But in this example, we'll just do a
    * single encryption operation with it (which is not very efficient).
    */

    tfm = crypto_alloc_skcipher("xts(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err("Error allocating xts(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    /* Allocate a request object */
    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        res = -ENOMEM;
        goto free_tfm;
    }

    res = trm_aes_operation(tfm, req, key, AES_KEY_SIZE, data, datasize, mode);

    skcipher_request_free(req);
free_tfm:
    crypto_free_skcipher(tfm);
    return res;
}


int trm_aes_decrypt(uint8_t *key, void *data, size_t datasize) {
    return prepare_skcipher(key, data, datasize, AES_DECRYPT);
}

int trm_aes_encrypt(uint8_t *key, void *data, size_t datasize) {
    return prepare_skcipher(key, data, datasize, AES_ENCRYPT);
}

int trm_aes_self_test(void) {
    char *data, *key, *h1, *h2, *h3, *h4;
    int err;
    size_t datasize = 365;

    data = kzalloc(datasize, GFP_KERNEL);
    if (!data) return -ENOMEM;
    random_bytes(data, datasize);
    h1 = to_hexstring(data, datasize);
    printk(KERN_INFO PFX "Raw data -- %s\n", h1);
    kfree(h1);
    
    key = kzalloc(AES_KEY_SIZE, GFP_KERNEL);
    if (!key) {
        err = -ENOMEM;
        goto free_data;
    }
    random_bytes(key, AES_KEY_SIZE);
    h2 = to_hexstring(key, AES_KEY_SIZE);
    printk(KERN_INFO PFX "Key -- %s\n", h2);
    kfree(h2);

    // Do encryption.
    err = trm_aes_encrypt(key, data, datasize);
    h3 = to_hexstring(data, datasize);
    printk(KERN_INFO PFX "Cipher(%d) -- %s\n", err, h3);
    kfree(h3);

    // Do decryption.
    if (!err) {
        err += 2 * trm_aes_decrypt(key, data, datasize);
        h4 = to_hexstring(data, datasize);
        printk(KERN_INFO PFX "Plain(%d) -- %s\n", err, h4);
        kfree(h4);
    } else {
        printk(KERN_INFO PFX "Encryption failed, skipp decryption.\n");
    }

    kfree(key);
free_data:
    kfree(data);
    return err;
}