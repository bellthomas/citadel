#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <linux/mutex.h>
#include <linux/dcache.h>

#include "../../includes/citadel.h"
#include "../../includes/file.h"


/*
 *	Check file permissions before accessing an open file.  This hook is
 *	called by various operations that read or write files.  A security
 *	module can use this hook to perform additional checking on these
 *	operations, e.g.  to revalidate permissions on use to support privilege
 *	bracketing or policy changes.  Notice that this hook is used when the
 *	actual read/write operations are performed, whereas the
 *	inode_security_ops hook is called when a file is opened (as well as
 *	many other operations).
 *	Caveat:  Although this hook can be used to revalidate permissions for
 *	various system call operations that read or write files, it does not
 *	address the revalidation of permissions for memory-mapped files.
 *	Security modules must handle this separately if they need such
 *	revalidation.
 *	@file contains the file structure being accessed.
 *	@mask contains the requested permissions.
 *	Return 0 if permission is granted.
 */
int trm_file_permission(struct file *file, int mask) {
    struct dentry *f_dentry = file->f_path.dentry;
    citadel_inode_data_t *inode_data = trm_dentry(f_dentry);
    citadel_task_data_t *task_data = citadel_cred(current_cred());

    task_housekeeping();
    inode_housekeeping(inode_data, f_dentry);
    
    // Don't care if this file isn't under our protection.
    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        return can_access(f_dentry->d_inode, CITADEL_OP_FILE_OPEN);
    }

    return 0;
}


/*
 *	@file contains the file structure.
 *	@cmd contains the operation to perform.
 *	@arg contains the operational arguments.
 *	Check permission for an ioctl operation on @file.  Note that @arg
 *	sometimes represents a user space pointer; in other cases, it may be a
 *	simple integer value.  When @arg represents a user space pointer, it
 *	should never be used by the security module.
 *	Return 0 if permission is granted.
 */
int trm_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    task_housekeeping();
    return 0;
}


/*
 *	Save open-time permission checking state for later use upon
 *	file_permission, and recheck access if anything has changed
 *	since inode_permission.
 */
int trm_file_open(struct file *file) {
    struct dentry *f_dentry = file->f_path.dentry;
    citadel_inode_data_t *inode_data = trm_dentry(f_dentry);
    citadel_task_data_t *task_data = citadel_cred(current_cred());

    task_housekeeping();

    // Don't care if this file isn't under our protection.
    if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
        return can_access(f_dentry->d_inode, CITADEL_OP_FILE_OPEN);
    }

    return 0;
}