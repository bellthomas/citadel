
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

	// char *path;
    struct dentry *f_dentry = file->f_path.dentry;
    struct inode_trm *current_inode_trm = trm_dentry(f_dentry);

    global_housekeeping(current_inode_trm, f_dentry);

    // Don't care if this file isn't under our protection.
    if (!current_inode_trm->in_realm) return 0;

    // Log for debug.
    // path = get_path_for_dentry(f_dentry);
    // if(path) {
    //     printk(PFX "trm_file_permission for %s (mask:%d)\n", path, mask);
    //     kfree(path);
    // }

    return 0;
}