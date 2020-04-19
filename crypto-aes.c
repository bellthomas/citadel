#include "includes/crypto.h"

#define AES_ENCRYPT 1
#define AES_DECRYPT 2
#define AES_KEY_SIZE 16

// Parameters to GCM-AES-128.
#define IV_LENGTH 12
#define TAG_LENGTH 16


struct tcrypt_result {
    struct completion completion;
    int err;
};


void aead_work_done(struct crypto_async_request *req, int err) {
    struct tcrypt_result *res = req->data;
    printk(KERN_INFO "LSM/TRM: aead_tcrypt_complete -> %d\n", err);
    if (err == -EINPROGRESS)
        return;

    res->err = err;
    complete(&res->completion);
}

int aead_wait_async_op(struct tcrypt_result *tr, int ret) {
    if (ret == -EINPROGRESS || ret == -EBUSY) {
        wait_for_completion(&tr->completion);
        reinit_completion(&tr->completion);
        ret = tr->err;
    }
    return ret;
}


static int trm_aes_operation(struct crypto_aead *tfm, struct aead_request *req, 
                             u8 *key, size_t key_size, void *data, size_t datasize, int mode, void *out, size_t *outlen) {

//     struct scatterlist sg;
    struct scatterlist plaintext[1];
    struct scatterlist ciphertext[1];
    unsigned char *plaindata = NULL;
    unsigned char *cipherdata = NULL;
    struct tcrypt_result result;
    u8 iv[IV_LENGTH];
    int err;
    size_t outsize;
     
    outsize = (mode == AES_ENCRYPT) ? datasize + TAG_LENGTH : datasize - TAG_LENGTH;
    if (mode == AES_ENCRYPT) printk(PFX "Encrypting: %ld -> %ld", datasize, outsize);
    else printk(PFX "Decrypting: %ld -> %ld", datasize, outsize);

    init_completion(&result.completion);

    printk(KERN_INFO PFX "Starting AES operation\n");
    err = crypto_aead_setkey(tfm, key, key_size);
    if (err) {
        pr_err(PFX "Error setting key: %d\n", err);
        goto bail;
    }

    /* Initialize the IV */
    memset(iv, 0, sizeof(iv));
    // get_random_bytes(iv, sizeof(iv));

    /* Set authentication tag length */
    if(crypto_aead_setauthsize(tfm, TAG_LENGTH)) {
        pr_info(PFX "Tag size could not be authenticated\n");
        err = -EAGAIN;
        goto bail;
    }

    /* Set IV size */
    // iv_len = crypto_aead_ivsize(tfm);
    // if (!(iv_len)){
    //     pr_info("IV size could not be authenticated\n");
    //     err = -EAGAIN;
    //     goto bail;
    // }
    // pr_info(PFX "IV size: %d\n", iv_len);
        

    plaindata  = kmalloc(datasize + TAG_LENGTH, GFP_KERNEL);
    cipherdata = kmalloc(datasize + TAG_LENGTH, GFP_KERNEL);
    if(!plaindata || !cipherdata) {
        printk("Memory not availaible\n");
        err = -ENOMEM;
        goto bail;
    }


    memcpy(plaindata, data, datasize);
    memset(plaindata + datasize, 0, TAG_LENGTH);

    memset(cipherdata, 0, datasize + TAG_LENGTH); // TODO bug
    // memset(gmacdata, 0, 16);

    sg_init_one(&plaintext[0], plaindata, datasize + TAG_LENGTH);
    sg_init_one(&ciphertext[0], cipherdata, datasize + TAG_LENGTH);

    // To avoid panicking.
    // new_cipher = kmalloc(PAGE_SIZE, GFP_KERNEL);
    // if (!new_cipher) goto out;
    // sg_init_table(ciphertext, 1);
    // sg_set_buf(&ciphertext[0], new_cipher, datasize);
    // sg_init_one(&gmactext[0], gmacdata, 128);


    aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, aead_work_done, &result);
    crypto_aead_clear_flags(tfm, ~0);

    aead_request_set_crypt(req, &plaintext[0], &ciphertext[0], datasize, iv);
    // aead_request_set_assoc(req, gmactext, datasize);
    // aead_request_set_assoc(req, NULL, 0);
    aead_request_set_ad(req, 0);
    crypto_aead_setauthsize(tfm, 16);

    printk(PFX "Pre aead_op...\n");

    if (mode == AES_ENCRYPT) err = aead_wait_async_op(&result, crypto_aead_encrypt(req));
    else err = aead_wait_async_op(&result, crypto_aead_decrypt(req));
    if (err) {
        pr_err(PFX "AES processing error: %d\n", err);
        goto bail;
    }
//     /*
//      * Encrypt the data in-place.
//      *
//      * For simplicity, in this example we wait for the request to complete
//      * before proceeding, even if the underlying implementation is asynchronous.
//      *
//      * To decrypt instead of encrypt, just change crypto_aead_encrypt() to
//      * crypto_aead_decrypt().
//      */
//     sg_init_one(&sg, data, datasize);
//     aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG, aead_tcrypt_complete, &result);
//     aead_request_set_crypt(req, &sg, &sg, datasize, iv);
//     aead_request_set_ad(req, TAG_LENGTH);

//     if (mode == AES_ENCRYPT) err = aead_wait_async_op(&result, crypto_aead_encrypt(req));
//     else err = aead_wait_async_op(&result, crypto_aead_decrypt(req));
//     if (err) {
//         pr_err(PFX "AES processing error: %d\n", err);
//         goto out;
//     }
    // sg_copy_from_buffer(ciphertext, sg_nents(ciphertext), new_cipher, datasize + 16);
    // kfree(new_cipher);
    memcpy(out, cipherdata, outsize);
    *outlen = outsize;
bail:
    kfree(plaindata);
    kfree(cipherdata);
    return err;
}

void random_bytes(uint8_t *key, size_t key_len) {
    get_random_bytes(key, key_len);
}

int prepare_aead(uint8_t *key, void *data, size_t datasize, int mode, void *out, size_t *outlen) {
    struct crypto_aead *tfm = NULL;
    struct aead_request *req = NULL;
    int res;

    /*
    * Allocate a tfm (a transformation object) and set the key.
    *
    * In real-world use, a tfm and key are typically used for many
    * encryption/decryption operations.  But in this example, we'll just do a
    * single encryption operation with it (which is not very efficient).
    */

    tfm = crypto_alloc_aead("gcm(aes)", 0, 0);
    if (IS_ERR(tfm)) {
        pr_err(PFX "Error allocating gcm(aes) handle: %ld\n", PTR_ERR(tfm));
        return PTR_ERR(tfm);
    }

    /* Allocate a request object */
    req = aead_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        res = -ENOMEM;
        goto free_tfm;
    }

    res = trm_aes_operation(tfm, req, key, AES_KEY_SIZE, data, datasize, mode, out, outlen);

    aead_request_free(req);
free_tfm:
    crypto_free_aead(tfm);
    return res;
}


int trm_aes_decrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen) {
    return prepare_aead(key, data, datasize, AES_DECRYPT, out, outlen);
}

int trm_aes_encrypt(uint8_t *key, void *data, size_t datasize, void *out, size_t *outlen) {
    return prepare_aead(key, data, datasize, AES_ENCRYPT, out, outlen);
}

int trm_aes_self_test(void) {
    char *data, *key, *cipher, *plain;
    char *h1, *h2, *h3, *h4;
    int err;
    size_t datasize = 365;
    size_t cipher_len, plainlen;

    data = kzalloc(datasize, GFP_KERNEL);
    if (!data) return -ENOMEM;
    random_bytes(data, datasize + TAG_LENGTH + IV_LENGTH);
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
    
    cipher = kzalloc(datasize + TAG_LENGTH, GFP_KERNEL);
    err = trm_aes_encrypt(key, data, datasize, cipher, &cipher_len);
    h3 = to_hexstring(cipher, cipher_len);
    printk(KERN_INFO PFX "Cipher(%d) -- %s\n", err, h3);
    kfree(h3);

    plain = kzalloc(datasize + TAG_LENGTH, GFP_KERNEL);
    err = trm_aes_decrypt(key, cipher, cipher_len, plain, &plainlen);
    h4 = to_hexstring(plain, plainlen);
    printk(KERN_INFO PFX "Plain(%d) -- %s\n", err, h4);
    kfree(h4);


    // // Do decryption.
    // if (!err) {
    //     err += 2 * trm_aes_decrypt(key, data, datasize);
    //     h4 = to_hexstring(data, datasize);
    //     printk(KERN_INFO PFX "Plain(%d) -- %s\n", err, h4);
    //     kfree(h4);
    // } else {
    //     printk(KERN_INFO PFX "Encryption failed, skip decryption.\n");
    // }
    kfree(plain);
    kfree(cipher);
    kfree(key);
free_data:
    kfree(data);
    return err;
}