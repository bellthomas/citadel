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

/* LSM's BLOB allocation. */

struct task_trm {
    uint8_t t_data;
};

struct inode_trm {
    uint8_t i_data;
    struct mutex lock;
};

struct lsm_blob_sizes trm_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct task_trm),
	.lbs_file = 0, //sizeof(struct smack_known *),
	.lbs_inode = sizeof(struct inode_trm),
	.lbs_ipc = 0, //sizeof(struct smack_known *),
	.lbs_msg_msg = 0 //sizeof(struct smack_known *),
};


static int rsa_available = 0;
static int secondary = 0;
struct dentry *integrity_dir;
struct dentry *challenge_file;
struct dentry *update_file;

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
static inline struct inode_trm *trm_inode(const struct inode *inode) {
	return inode->i_security + trm_blob_sizes.lbs_inode;
}
static inline struct task_trm *trm_cred(const struct cred *cred) {
	return cred->security + trm_blob_sizes.lbs_cred;
}

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


static char *trm_get_dentry_path(struct dentry *dentry, char * const buffer,
				    const int buflen)
{
	char *pos = ERR_PTR(-ENOMEM);

	if (buflen >= 256) {
		pos = dentry_path_raw(dentry, buffer, buflen - 1);
		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
			struct inode *inode = d_backing_inode(dentry);

			if (inode && S_ISDIR(inode->i_mode)) {
				buffer[buflen - 2] = '/';
				buffer[buflen - 1] = '\0';
			}
		}
	}
	return pos;
}

/**
 * smack_inode_rename - Smack check on rename
 * @old_inode: unused
 * @old_dentry: the old object
 * @new_inode: unused
 * @new_dentry: the new object
 *
 * Read and write access is required on both the old and
 * new directories.
 *
 * Returns 0 if access is permitted, an error code otherwise
 */
static int trm_inode_rename(struct inode *old_inode,
			      struct dentry *old_dentry,
			      struct inode *new_inode,
			      struct dentry *new_dentry)
{
    int xattr_success;
    char *pos;
    char *pathname = NULL;
	struct dentry *dentry;
    int pathname_len = 1024;
    struct inode_trm *itp = trm_inode(new_inode);

    dentry = d_find_alias(new_inode);
    if (dentry) {
        pathname = kzalloc(pathname_len, GFP_KERNEL);
        pos = trm_get_dentry_path(dentry, pathname, pathname_len);
        if (!IS_ERR(pos)) {
            printk(PFX "trm_inode_rename() -- from %s\n", pos);
            
            xattr_success = security_inode_setxattr(dentry, "security.citadel_protected", (const void*)"yes", 4, 0);
            printk(PFX "xattr setting: %d\n", xattr_success);
            xattr_success = __vfs_setxattr_noperm(dentry, "security.citadel_protected_2", (const void*)"yes", 4, 0);
            printk(PFX "xattr setting 2: %d\n", xattr_success);
        } else {
            printk(PFX "trm_inode_rename() -- error\n");
        }
        kfree(pathname);
    }


	// int rc;
	// struct smack_known *isp;
	// struct smk_audit_info ad;

	// smk_ad_init(&ad, __func__, LSM_AUDIT_DATA_DENTRY);
	// smk_ad_setfield_u_fs_path_dentry(&ad, old_dentry);

	// isp = smk_of_inode(d_backing_inode(old_dentry));
	// rc = smk_curacc(isp, MAY_READWRITE, &ad);
	// rc = smk_bu_inode(d_backing_inode(old_dentry), MAY_READWRITE, rc);

	// if (rc == 0 && d_is_positive(new_dentry)) {
	// 	isp = smk_of_inode(d_backing_inode(new_dentry));
	// 	smk_ad_setfield_u_fs_path_dentry(&ad, new_dentry);
	// 	rc = smk_curacc(isp, MAY_READWRITE, &ad);
	// 	rc = smk_bu_inode(d_backing_inode(new_dentry), MAY_READWRITE, rc);
	// }
    printk(PFX "Doing rename -- %d\n", itp->i_data);
	return 0;
}


/**
 * init_inode_smack - initialize an inode security blob
 * @inode: inode to extract the info from
 * @skp: a pointer to the Smack label entry to use in the blob
 *
 */
static void init_inode_trm(struct inode *inode) { //, struct smack_known *skp
	struct inode_trm *itp = trm_inode(inode);
    itp->i_data = 23;
	mutex_init(&itp->lock);
}

static int trm_inode_alloc_security(struct inode *inode) {
	init_inode_trm(inode);
	return 0;
}

/**
 * smack_inode_init_security - copy out the smack from an inode
 * @inode: the newly created inode
 * @dir: containing directory object
 * @qstr: unused
 * @name: where to put the attribute name
 * @value: where to put the attribute value
 * @len: where to put the length of the attribute
 *
 * Returns 0 if it all works out, -ENOMEM if there's no memory
 */
static int trm_inode_init_security(struct inode *inode, struct inode *dir,
				     const struct qstr *qstr, const char **name,
				     void **value, size_t *len)
{
    return 0;
}


/**
 * smack_inode_setsecurity - set smack xattrs
 * @inode: the object
 * @name: attribute name
 * @value: attribute value
 * @size: size of the attribute
 * @flags: unused
 *
 * Sets the named attribute in the appropriate blob
 *
 * Returns 0 on success, or an error code
 */
// static int smack_inode_setsecurity(struct inode *inode, const char *name,
// 				   const void *value, size_t size, int flags)
// {
// 	struct smack_known *skp;
// 	struct inode_smack *nsp = smack_inode(inode);
// 	struct socket_smack *ssp;
// 	struct socket *sock;
// 	int rc = 0;

// 	if (value == NULL || size > SMK_LONGLABEL || size == 0)
// 		return -EINVAL;

// 	skp = smk_import_entry(value, size);
// 	if (IS_ERR(skp))
// 		return PTR_ERR(skp);

// 	if (strcmp(name, XATTR_SMACK_SUFFIX) == 0) {
// 		nsp->smk_inode = skp;
// 		nsp->smk_flags |= SMK_INODE_INSTANT;
// 		return 0;
// 	}



static int trm_inode_setxattr(struct dentry *dentry, const char *name,
				  const void *value, size_t size, int flags)
{
    // struct inode *inode = d_backing_inode(dentry);
	// struct inode_security_struct *isec;
	// struct superblock_security_struct *sbsec;
	// struct common_audit_data ad;
	// u32 newsid, sid = current_sid();
	// int rc = 0;

    printk(PFX "trm_inode_setxattr() -- %s", name);

    return 0;
}

// ----------------------------------------------------------------//
// Region: securityfs operations.

static const struct file_operations challenge_file_ops = { .read = challenge_read, .write = challenge_receive };
static const struct file_operations update_file_ops = { .read = update_read, .write = update_receive };

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


int is_rsa_available(void) {
    return rsa_available;
}




/*
 * The hooks we wish to be installed.
 */
static struct security_hook_list trm_hooks[] __lsm_ro_after_init = {
    LSM_HOOK_INIT(bprm_check_security, trm_bprm_check_security),
    LSM_HOOK_INIT(inode_permission, trm_inode_permission),
    LSM_HOOK_INIT(task_prctl, trm_task_prctl),

    LSM_HOOK_INIT(inode_alloc_security, trm_inode_alloc_security),
	LSM_HOOK_INIT(inode_init_security, trm_inode_init_security),
    LSM_HOOK_INIT(inode_rename, trm_inode_rename),
    LSM_HOOK_INIT(inode_setxattr, trm_inode_setxattr),

    // LSM_HOOK_INIT(inode_setsecurity, trm_inode_setsecurity), // for xattrs
};


static int __init trm_init(void) {
    // struct cred *cred = (struct cred *) current->cred;
    security_add_hooks(trm_hooks, ARRAY_SIZE(trm_hooks), "trm");
    printk(KERN_INFO PFX "(Trusted Reference Monitor) initialized.\n");
    return 0;
}

/*
 * Ensure the initialization code is called.
 */
DEFINE_LSM(trm_init) = {
    .init = trm_init,
    .blobs = &trm_blob_sizes,
    .name = "trm",
};
