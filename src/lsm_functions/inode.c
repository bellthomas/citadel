
#include "../../includes/inode.h"


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
int trm_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			         struct inode *new_inode, struct dentry *new_dentry)
{
	return -EOPNOTSUPP;
}



/*
 *	Allocate and attach a security structure to @inode->i_security.  The
 *	i_security field is initialized to NULL when the inode structure is
 *	allocated.
 *	@inode contains the inode structure.
 *	Return 0 if operation was successful.
 */
int trm_inode_alloc_security(struct inode *inode) {
	struct inode_trm *itp = trm_inode(inode);
    itp->in_realm = false;
	itp->needs_xattr_update = false;
	itp->checked_disk_xattr = false;
	itp->data = 234;
	mutex_init(&itp->lock);
	return 0;
}


/*
 *	Obtain the security attribute name suffix and value to set on a newly
 *	created inode and set up the incore security field for the new inode.
 *	This hook is called by the fs code as part of the inode creation
 *	transaction and provides for atomic labeling of the inode, unlike
 *	the post_create/mkdir/... hooks called by the VFS.  The hook function
 *	is expected to allocate the name and value via kmalloc, with the caller
 *	being responsible for calling kfree after using them.
 *	If the security module does not use security attributes or does
 *	not wish to put a security attribute on this particular inode,
 *	then it should return -EOPNOTSUPP to skip this processing.
 *	@inode contains the inode structure of the newly created inode.
 *	@dir contains the inode structure of the parent directory.
 *	@qstr contains the last path component of the new object
 *	@name will be set to the allocated name suffix (e.g. selinux).
 *	@value will be set to the allocated attribute value.
 *	@len will be set to the length of the value.
 *	Returns 0 if @name and @value have been successfully set,
 *	-EOPNOTSUPP if no security attribute is needed, or
 *	-ENOMEM on memory allocation failure.
 */
int trm_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len) {
	struct inode_trm *new_inode_trm = trm_inode(inode);
	struct inode_trm *parent_inode_trm = trm_inode(dir);

	// Hierarchical subsumption.
	if (parent_inode_trm->in_realm && !new_inode_trm->in_realm) {
		printk(PFX "trm_inode_init_security setting child (%ld)\n", inode->i_ino);
		new_inode_trm->in_realm = true;
		new_inode_trm->needs_xattr_update = true;
	}

	return -EOPNOTSUPP; // We don't use security attributes here.
}



/*
 *	Check permission before creating a new hard link to a file.
 *	@old_dentry contains the dentry structure for an existing
 *	link to the file.
 *	@dir contains the inode structure of the parent directory
 *	of the new link.
 *	@new_dentry contains the dentry structure for the new link.
 *	Return 0 if permission is granted.
 */
int trm_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	char *hex_id, *identifier;
    char *pathname = NULL;
	int res;
	// struct inode *inode = d_backing_inode(old_dentry);
	struct inode_trm *old_inode_trm = trm_dentry(old_dentry);

	// global_housekeeping(old_inode_trm, old_dentry);

	// Copy metadata to the new inode link.
	if (old_inode_trm) {
		if (old_inode_trm->in_realm) {
			if (new_dentry->d_inode) {
				printk(PFX "trm_inode_link, in realm and got new inode\n");
			} else {
				printk(PFX "trm_inode_link, in realm and NOT got new inode\n");
			}

			if (old_dentry->d_inode) {
				printk(PFX "trm_inode_link, in realm and got old inode\n");
			} else {
				printk(PFX "trm_inode_link, in realm and NOT got old inode\n");
			}
		}
	} else {
		printk(PFX "no old_inode_trm\n");
	}

	return 0;
}


/*
 *	Change the security context of an inode.  Updates the
 *	incore security context managed by the security module and invokes the
 *	fs code as needed (via __vfs_setxattr_noperm) to update any backing
 *	xattrs that represent the context.  Example usage:  NFS server invokes
 *	this hook to change the security context in its incore inode and on the
 *	backing filesystem to a value provided by the client on a SETATTR
 *	operation.
 *	Must be called with inode->i_mutex locked.
 *	@dentry contains the inode we wish to set the security context of.
 *	@ctx contains the string which we wish to set in the inode.
 *	@ctxlen contains the length of @ctx.
 */
// int trm_inode_setsecctx(struct dentry *dentry, void *ctx, u32 ctxlen) {
// 	struct inode_trm *current_inode_trm = trm_dentry(dentry);
// 	char *pos;
//     char *pathname = NULL;
// 	int pathname_len = 1024;
// 	int res;
// 	size_t xattr_size;

// 	if (current_inode_trm->in_realm) {
// 		printk(PFX "trm_inode_setsecctx and in realm\n");
// 		// Check if the xattr is set.
// 		xattr_size = __vfs_getxattr(dentry, d_backing_inode(dentry), TRM_XATTR_REALM_NAME, NULL, 0);
//        	if (xattr_size == 0) {
// 			// context is initialised by xattr is blank; update.
// 			res = __set_xattr_in_realm(dentry);
// 			printk(PFX "xattr setting success: %d\n", res);

// #if TRM_DEBUG == 1
// 			// Log for debug.
// 			pathname = kzalloc(pathname_len, GFP_KERNEL);
// 			if(pathname) {
// 				pos = get_dentry_path(dentry, pathname, pathname_len);
// 				if (!IS_ERR(pos)) {
// 					printk(PFX "[HIER_SUB] Setting in_realm for %s\n", pos);
// 				}
// 				kfree(pathname);
// 			}
// #endif
// 		}
// 	}

// 	return -EOPNOTSUPP; // We don't use security attributes here.
// }

// int trm_inode_notifysecctx(struct inode *inode, void *ctx, u32 ctxlen) {
// 	struct inode_trm *current_inode_trm = trm_inode(inode);
// 	if(current_inode_trm->in_realm) {
// 		printk(PFX "trm_inode_notifysecctx and in realm");
// 	}
// 	return -EOPNOTSUPP;
// }


void trm_d_instantiate(struct dentry *dentry, struct inode *inode) {
	struct inode_trm *current_inode_trm = trm_inode(inode);
	if(current_inode_trm->in_realm) {
		dentry->d_inode = inode;
		realm_housekeeping(current_inode_trm, dentry);
		dentry->d_inode = NULL;
		printk(PFX "trm_d_instantiate (in_realm, %ld)\n", inode->i_ino);
	}
}




/* Region: xattrs */
int trm_inode_setxattr(struct dentry *dentry, const char *name,
				       const void *value, size_t size, int flags)
{
	int rc = 0;
    char *pathname = NULL;

	// Check for security.citadel.install
	if (!strcmp(name, TRM_XATTR_INSTALL_NAME)) {
		if(system_ready())
			rc = xattr_enclave_installation(value, size, dentry) ? -XATTR_REJECTED_SIGNAL : -XATTR_ACCEPTED_SIGNAL;
		else
			rc = -ECANCELED; // Can't process this operation yet.
		
#if TRM_DEBUG == 1
		pathname = get_path_for_dentry(dentry);
		if(pathname) {
			printk(PFX "security.citadel.install for %s (err=%d)\n", pathname, rc);
			kfree(pathname);
		}
#endif

		return rc;
	}

	// Normal, non-security.citadel.* attribute.
	if (strncmp(name, TRM_XATTR_PREFIX, strlen(TRM_XATTR_PREFIX))) {
		return cap_inode_setxattr(dentry, name, value, size, flags);
	}

	// No-one can set this xattr apart from the kernel.
	printk(PFX "Rejected trm_inode_setxattr() -- %s\n", name);
    return -EPERM; //(inode_owner_or_capable(inode) ? 0 : -EPERM);
}

void trm_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
	struct inode_trm *current_inode_trm = trm_dentry(dentry);
    char *pathname = NULL;



	if (current_inode_trm) {
		// Do housekeeping.
		global_housekeeping(current_inode_trm, dentry);

		if (current_inode_trm->in_realm) {

			// Log for debug.
			pathname = get_path_for_dentry(dentry);
			if(pathname) {
				printk(PFX "trm_inode_post_setxattr for %s\n", pathname);
				kfree(pathname);
			}
		}
	}
	return;
}

int trm_inode_getxattr(struct dentry *dentry, const char *name)
{
	struct inode_trm *current_inode_trm = trm_dentry(dentry);
	if(current_inode_trm)
		global_housekeeping(current_inode_trm, dentry);
	return 0;
}
int trm_inode_listxattr(struct dentry *dentry) {
	struct inode_trm *current_inode_trm = trm_dentry(dentry);
	if(current_inode_trm)
		global_housekeeping(current_inode_trm, dentry);
	return 0;
}

int trm_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct inode_trm *current_inode_trm = trm_dentry(dentry);
	if(current_inode_trm)
		global_housekeeping(current_inode_trm, dentry);

	if (strncmp(name, TRM_XATTR_PREFIX, strlen(TRM_XATTR_PREFIX))) {
		return cap_inode_removexattr(dentry, name);
	}

	/* No one is allowed to remove a Citadel security label. */
	return -EACCES;
}