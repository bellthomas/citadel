/*
 * trm_lsm.c
 *
 * Allow/deny execution of programs to non-root users, by looking for
 * a security attribute upon the file.
 *
 * To set a program as trmed you must add a label to the target,
 * for example:
 *
 *     setfattr -n security.trmed -v 1 /bin/dash
 *
 * To confirm there is a label present you can use the dump option:
 *
 *     ~# getfattr -d -m security /bin/dash
 *     getfattr: Removing leading '/' from absolute path names
 *     # file: bin/dash
 *     security.trmed="1"
 *
 * Finally to revoke the label, and deny execution once more:
 *
 *     ~# setfattr -x security.trmed /bin/dash
 *
 * There is a helper tool located in `samples/trm` which wraps
 * that for you, in a simple way.
 *
 * Steve
 * --
 *
 */


#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>

// #include "trm_keys.h"
// #include "trm_keys2.h"
#include "includes/trm.h"
#include "includes/ticket_cache.h"
#include "includes/crypto.h"

static int rsa_available = 0;
static int secondary = 0;
struct dentry *integrity_dir;
struct dentry *challenge_file;
struct dentry *request_file;

/*
 * Perform a check of a program execution/map.
 *
 * Return 0 if it should be allowed, -EPERM on block.
 */
static int trm_bprm_check_security(struct linux_binprm *bprm) {
    // The current task & the UID it is running as.
    // const struct task_struct *task = current;
    // kuid_t uid = task->cred->uid;
    secondary++;
    // printk(KERN_INFO "TRM: bprm_check_security() check from uid: %d on %s [%d]\n", uid.val, bprm->filename, secondary);
    return 0;
}

static int trm_inode_permission(struct inode *inode, int mask) {
    const struct task_struct *task = current;
    kuid_t uid = task->cred->uid;

    kuid_t inode_uid = inode->i_uid;
    kgid_t inode_gid = inode->i_gid;
    unsigned int inode_uid_i = inode_uid.val;
    unsigned int inode_gid_i = inode_gid.val;
    if(inode_uid_i != 0 && inode_gid_i != 0 && (unsigned int)uid.val != 0) {
        // secondary++;
        // printk(KERN_INFO "TRM: inode_permissions() check from uid: %d on (%d, %d) [%d]\n", uid.val, inode_uid_i, inode_gid_i, secondary);
    }
    return 0;
}

static int trm_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    return 0;
}



// ----------------------------------------------------------------//
// Region: securityfs operations.

static ssize_t response_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos) {
    char *data, *decipher, *decipher_hex;
    int error, decipher_len;
    error = 0;

    // Return -EPERM for failed decrypt.
    printk(KERN_INFO PFX "test_write(%ld, %lld)", count, *ppos);
    if (!count || count > 256) // TODO: make max count a defines
        return -ENOMEM;

    if (!rsa_available) {
        printk(KERN_INFO PFX "Rejected ../request write because RSA not available yet.");
        return (ssize_t)0;
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

static ssize_t challenge_read(struct file *file, char __user *buf, size_t count, loff_t *ppos) {
    const char *data;
    loff_t pos, len;

    char *cipher;
    int cipher_len;

    printk(KERN_INFO PFX "test_read()");
    if (!rsa_available) {
        printk(KERN_INFO PFX "Rejected ../challenge read because RSA not available yet.");
        return (ssize_t)0;
    }

    // Generate secret message.
    data = "Secret message here.\n";
    pos = *ppos;
    len = 21;

    cipher = trm_rsa_encrypt((char*)data, len, &cipher_len);
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
    return cipher_len;
}

static const struct file_operations challenge_file_ops = { .read = challenge_read };
static const struct file_operations request_file_ops = { .write = response_receive };

static int __init integrity_fs_init(void)
{
	integrity_dir = securityfs_create_dir("trm", NULL);
	if (IS_ERR(integrity_dir)) {
		int ret = PTR_ERR(integrity_dir);

		if (ret != -ENODEV)
			pr_err("Unable to create integrity sysfs dir: %d\n", ret);
		integrity_dir = NULL;
		return ret;
	}

    challenge_file = securityfs_create_file(
        "challenge", // name
        S_IRUSR | S_IRGRP,
        integrity_dir,
        (void*)"test",
        &challenge_file_ops
    );

    request_file = securityfs_create_file(
        "response", // name
        S_IWUSR | S_IWGRP,
        integrity_dir,
        (void*)"test",
        &request_file_ops
    );

	return 0;
}

late_initcall(integrity_fs_init)
// ----------------------------------------------------------------//



static int __init crypto_init(void) {
    int res, res2;
    res = trm_rsa_self_test();
    res2 = trm_aes_self_test();
    if(!res) {
        printk(KERN_INFO PFX "RSA support enabled.\n");
        rsa_available = 1;
    } else {
        printk(KERN_INFO PFX "Crypto Test -- %d\n", res);
    }
    return res;
}
late_initcall(crypto_init)
// ----------------------------------------------------------------//



/*
 * The hooks we wish to be installed.
 */
static struct security_hook_list trm_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(bprm_check_security, trm_bprm_check_security),
    LSM_HOOK_INIT(inode_permission, trm_inode_permission),
    LSM_HOOK_INIT(task_prctl, trm_task_prctl),
};


static int __init trm_init(void) {
    
    int aesni_res;
    aesni_res = 1;
    // aesni_res = aes128_self_test();

    aesni_res = test_cache();
    //request_module("trm_lkm");
    security_add_hooks(trm_hooks, ARRAY_SIZE(trm_hooks), "trm");
    printk(KERN_INFO PFX "(Trusted Reference Monitor) initialized (AESNI: %d)\n", aesni_res);
    // printk(KERN_INFO PFX "Key: %d bytes\n", generated_key_pub_len);


    // Create securityfs hooks.
    return 0;
}

/*
 * Ensure the initialization code is called.
 */
DEFINE_LSM(trm_init) = {
    .init = trm_init,
    .name = "trm",
};
