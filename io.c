
#include "includes/io.h"

ssize_t challenge_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char *data, *decipher, *decipher_hex;
    int error, decipher_len;
    error = 0;

    // Return -EPERM for failed decrypt.
    printk(KERN_INFO PFX "test_write(%ld, %lld)", count, *ppos);
    if (!count || count > CHALLENGE_MAX_SIZE) 
        return -ENOMEM;

    if (!is_rsa_available()) {
        printk(KERN_INFO PFX "Rejected ../request write because RSA not available yet.");
        return (ssize_t)count;
    }

    // Allocate kernel buffer.
    data = kzalloc(count + 1, GFP_NOFS);
    if (!data) return -ENOMEM;

    // Copy from userspace into the kernel buffer.
    if (copy_from_user(data, buf, count)) {
        printk(KERN_INFO PFX "Failed to copy data from userspace to kernel buffer.\n");
        error = -EFAULT;
        goto out;
    }
    
    decipher = trm_rsa_decrypt((char*)data, count, &decipher_len);
    if(decipher_len == 0) {
        printk(KERN_INFO PFX "Rejected ../request write(%ld) because RSA decryption failed.", count);
        error = -EFAULT;
        goto out;
    }

    decipher_hex = to_hexstring(decipher, decipher_len);
    printk(KERN_INFO PFX "Request -- %s\n", decipher_hex);
    kfree(decipher_hex);
    kfree(decipher);

    /* handling kaddr */
out:
    kfree(data);
    return count;
    // return error ? error : count;
}

ssize_t challenge_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {

    loff_t pos;
    char *cipher;
    size_t cipher_len;

    if (!is_rsa_available()) {
        printk(KERN_INFO PFX "Rejected ../challenge read because RSA not available yet.");
        return (ssize_t)count;
    }

    // Generate secret message.
    pos = *ppos;
    cipher = generate_challenge(&cipher_len);

    if (cipher_len == 0) {
        printk(KERN_INFO PFX "Rejected ../challenge read because RSA encryption failed.");
        return (ssize_t)0;
    }

    if (pos >= cipher_len || !count) return 0;

    cipher_len -= pos;
    if (count < cipher_len) cipher_len = count;

    /* handling */
    if (copy_to_user(buf, cipher, cipher_len)) return -EFAULT;
    *ppos += cipher_len;
    kfree(cipher);
    return cipher_len;
}


ssize_t update_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    return (ssize_t)0;
}

ssize_t update_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    return (ssize_t)0;
}