#include <linux/init.h>
#include <linux/types.h>
#include <linux/lsm_hooks.h>
#include <linux/dcache.h>

#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <linux/mutex.h>


#include "../includes/citadel.h"
#include "../includes/common.h"
#include "../includes/file_io.h"
#include "../includes/payload_io.h"
#include "../includes/ticket_cache.h"
#include "../includes/crypto.h"
#include "../includes/inode.h"
#include "../includes/file.h"
#include "../includes/task.h"
#include "../includes/socket.h"
#include "../includes/ipc.h"

static int rsa_available = 0;
static int aes_available = 0;

struct dentry *citadel_dir;
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
    task_housekeeping();
    return 0;
}


// ----------------------------------------------------------------//
// Region: securityfs operations.

static const struct file_operations challenge_file_ops = { .read = challenge_read, .write = challenge_receive };
static const struct file_operations update_file_ops = { .read = update_read, .write = update_receive };
static const struct file_operations ptoken_file_ops = { .read = ptoken_read };

static int __init integrity_fs_init(void)
{
	citadel_dir = securityfs_create_dir(_CITADEL_SECURITYFS_NS, NULL);
	if (IS_ERR(citadel_dir)) {
		int ret = PTR_ERR(citadel_dir);

		if (ret != -ENODEV)
			pr_err(PFX "Unable to create %s sysfs dir: %d\n", _CITADEL_SECURITYFS_NS, ret);
		citadel_dir = NULL;
		return ret;
	}

    challenge_file = securityfs_create_file(
        _CITADEL_SECURITYFS_CHALLENGE, // name
        S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
        citadel_dir,
        NULL,
        &challenge_file_ops
    );

    update_file = securityfs_create_file(
        _CITADEL_SECURITYFS_UPDATE, // name
        S_IRUSR | S_IRGRP | S_IWUSR | S_IWGRP,
        citadel_dir,
        NULL,
        &update_file_ops
    );

    ptoken_file = securityfs_create_file(
        _CITADEL_SECURITYFS_PTOKEN, // name
        S_IRUSR | S_IRGRP | S_IROTH,
        citadel_dir,
        NULL,
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

    // Provided by lsm_functions/inode.c
    LSM_HOOK_INIT(inode_alloc_security, trm_inode_alloc_security),
    LSM_HOOK_INIT(inode_init_security, trm_inode_init_security),
    LSM_HOOK_INIT(inode_free_security, trm_inode_free_security),
    // LSM_HOOK_INIT(inode_create, trm_inode_create),
    // LSM_HOOK_INIT(inode_permission, trm_inode_permission),
    LSM_HOOK_INIT(inode_link, trm_inode_link),
    // LSM_HOOK_INIT(inode_rename, trm_inode_rename),
    LSM_HOOK_INIT(inode_setxattr, trm_inode_setxattr),
    LSM_HOOK_INIT(inode_post_setxattr, trm_inode_post_setxattr),
    LSM_HOOK_INIT(inode_getxattr, trm_inode_getxattr),
    LSM_HOOK_INIT(inode_listxattr, trm_inode_listxattr),
	LSM_HOOK_INIT(inode_removexattr, trm_inode_removexattr),
    LSM_HOOK_INIT(inode_getsecurity, trm_inode_getsecurity),
    LSM_HOOK_INIT(inode_listsecurity, trm_inode_listsecurity),
    LSM_HOOK_INIT(d_instantiate, trm_d_instantiate),

    // Provided by lsm_functions/file.c
    LSM_HOOK_INIT(file_permission, trm_file_permission),
    LSM_HOOK_INIT(file_ioctl, trm_file_ioctl),
    LSM_HOOK_INIT(file_open, trm_file_open),

    // Provided by lsm_functions/task.c
    LSM_HOOK_INIT(cred_alloc_blank, trm_cred_alloc_blank),
    LSM_HOOK_INIT(cred_prepare, trm_cred_prepare),
    LSM_HOOK_INIT(task_prctl, trm_task_prctl),
    LSM_HOOK_INIT(task_kill, trm_task_kill),
    LSM_HOOK_INIT(task_free, trm_task_free),
    LSM_HOOK_INIT(cred_free, trm_cred_free),
    // LSM_HOOK_INIT(bprm_committed_creds, trm_bprm_committed_creds),

    // Provided by lsm_functions/socket.c
    LSM_HOOK_INIT(socket_post_create, trm_socket_post_create),
    LSM_HOOK_INIT(socket_socketpair, trm_socket_socketpair),
    LSM_HOOK_INIT(socket_bind, trm_socket_bind),
    LSM_HOOK_INIT(socket_accept, trm_socket_accept),
    LSM_HOOK_INIT(socket_sendmsg, trm_socket_sendmsg),
    LSM_HOOK_INIT(socket_recvmsg, trm_socket_recvmsg),
    LSM_HOOK_INIT(socket_shutdown, trm_socket_shutdown),

    // Provided by lsm_functions/ipc.c
    LSM_HOOK_INIT(shm_alloc_security, trm_ipc_alloc_security),
    LSM_HOOK_INIT(shm_free_security, trm_ipc_free_security),
    LSM_HOOK_INIT(shm_associate, trm_shm_associate),
    LSM_HOOK_INIT(shm_shmctl, trm_shm_shmctl),
    LSM_HOOK_INIT(shm_shmat, trm_shm_shmat),
};


static int __init citadel_init(void) {
    // struct cred *cred = (struct cred *) current->cred;
    security_add_hooks(citadel_hooks, ARRAY_SIZE(citadel_hooks), _CITADEL_LSM_NAME);
    printk(KERN_INFO PFX "Citadel Reference Monitor initialized.\n");
    return 0;
}

/*
 * Ensure the initialization code is called.
 */
DEFINE_LSM(citadel_init) = {
    .init = citadel_init,
    .blobs = &citadel_blob_sizes,
    .name = _CITADEL_LSM_NAME,
};
