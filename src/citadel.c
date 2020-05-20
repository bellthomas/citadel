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


#include "../includes/citadel.h"

static int rsa_available = 0;
static int aes_available = 0;
static int secondary = 0;
struct dentry *integrity_dir;
struct dentry *challenge_file;
struct dentry *update_file;
struct dentry *ptoken_file;

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


// Trying out inode-y things.


// static inline struct smack_known *smk_of_task_struct(const struct task_struct *t) {
// 	struct smack_known *skp;
// 	const struct cred *cred;

// 	rcu_read_lock();

// 	cred = __task_cred(t);
// 	skp = smk_of_task(smack_cred(cred));

// 	rcu_read_unlock();

// 	return skp;
// }

// static inline struct smack_known *tracker_of_current(void) {
// 	return smk_of_task(smack_cred(current_cred()));
// }




// ----------------------------------------------------------------//
// Region: securityfs operations.

static const struct file_operations challenge_file_ops = { .read = challenge_read, .write = challenge_receive };
static const struct file_operations update_file_ops = { .read = update_read, .write = update_receive };
static const struct file_operations ptoken_file_ops = { .read = ptoken_read };

static int __init integrity_fs_init(void)
{
	integrity_dir = securityfs_create_dir("citadel", NULL);
	if (IS_ERR(integrity_dir)) {
		int ret = PTR_ERR(integrity_dir);

		if (ret != -ENODEV)
			pr_err("Unable to create integrity sysfs dir: %d\n", ret);
		integrity_dir = NULL;
		return ret;
	}

    challenge_file = securityfs_create_file(
        "challenge", // name
        S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
        integrity_dir,
        (void*)"test",
        &challenge_file_ops
    );

    update_file = securityfs_create_file(
        "update", // name
        S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
        integrity_dir,
        (void*)"test",
        &update_file_ops
    );

    ptoken_file = securityfs_create_file(
        "get_ptoken", // name
        S_IRUSR | S_IRGRP | S_IROTH,
        integrity_dir,
        (void*)"test",
        &ptoken_file_ops
    );

	return 0;
}

late_initcall(integrity_fs_init)


// ----------------------------------------------------------------//
// Region: Crypto.

int is_rsa_available(void) {
    return rsa_available;
}

int is_aes_available(void) {
    return aes_available;
}

static void __init crypto_init(void) {
    int res_rsa, res_aes;

    // Check RSA.
    res_rsa = trm_rsa_self_test();
    if(!res_rsa) {
        printk(KERN_INFO PFX "RSA support enabled.\n");
        rsa_available = 1;
    } else {
        printk(KERN_INFO PFX "RSA Selftest -- %d\n", res_rsa);
    }

    // Check AES.
    res_aes = trm_aes_self_test();
    if(!res_rsa) {
        printk(KERN_INFO PFX "AES support enabled.\n");
        aes_available = 1;
    } else {
        printk(KERN_INFO PFX "AES Selftest -- %d\n", res_aes);
    }
}
late_initcall(crypto_init)


// ----------------------------------------------------------------//
// Region: Core LSM definitions.

/*
 * The hooks we wish to be installed.
 */
static struct security_hook_list citadel_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(bprm_check_security, trm_bprm_check_security),
    LSM_HOOK_INIT(inode_permission, trm_inode_permission),
    LSM_HOOK_INIT(task_prctl, trm_task_prctl),

    // Provided by lsm_functions/inode.c
    LSM_HOOK_INIT(inode_alloc_security, trm_inode_alloc_security),
    LSM_HOOK_INIT(inode_init_security, trm_inode_init_security),
    // LSM_HOOK_INIT(inode_create, trm_inode_create),
    LSM_HOOK_INIT(inode_link, trm_inode_link),
    // LSM_HOOK_INIT(inode_rename, trm_inode_rename),
    LSM_HOOK_INIT(inode_setxattr, trm_inode_setxattr),
    LSM_HOOK_INIT(inode_post_setxattr, trm_inode_post_setxattr),
    LSM_HOOK_INIT(inode_getxattr, trm_inode_getxattr),
    LSM_HOOK_INIT(inode_listxattr, trm_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, trm_inode_removexattr),
    // LSM_HOOK_INIT(inode_setsecurity, trm_inode_setsecurity), // for xattrs
    LSM_HOOK_INIT(d_instantiate, trm_d_instantiate),

    // Provided by lsm_functions/file.c
    LSM_HOOK_INIT(file_permission, trm_file_permission),

    // Provided by lsm_functions/task.c
    LSM_HOOK_INIT(cred_alloc_blank, trm_cred_alloc_blank),
    LSM_HOOK_INIT(cred_prepare, trm_cred_prepare),
};


static int __init citadel_init(void) {
    // struct cred *cred = (struct cred *) current->cred;
    security_add_hooks(citadel_hooks, ARRAY_SIZE(citadel_hooks), "trm");
    printk(KERN_INFO PFX "Citadel Reference Monitor initialized.\n");
    return 0;
}

/*
 * Ensure the initialization code is called.
 */
DEFINE_LSM(citadel_init) = {
    .init = citadel_init,
    .blobs = &citadel_blob_sizes,
    .name = "trm",
};
