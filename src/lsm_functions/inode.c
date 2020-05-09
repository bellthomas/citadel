
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

// Internal implementation.
int __trm_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			           struct inode *new_inode, struct dentry *new_dentry)
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
        pos = get_dentry_path(dentry, pathname, pathname_len);
        if (!IS_ERR(pos)) {
            // printk(PFX "trm_inode_rename() -- from %s\n", pos);
            // vfs_removexattr(dentry, "security.citadel_protected_2");
            // vfs_removexattr(dentry, "security.citadel_protected");
            // xattr_success = security_inode_setxattr(dentry, "security.citadel_protected", (const void*)"yes", 4, 0);
            // printk(PFX "xattr setting: %d\n", xattr_success);
            inode_lock(new_inode);
			xattr_success = __vfs_setxattr_noperm(dentry, "security.citadel", (const void*)"yes", 4, 0);
            inode_unlock(new_inode);
			printk(PFX "xattr setting: %d\n", xattr_success);
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

int trm_inode_rename(struct inode *old_inode, struct dentry *old_dentry,
			         struct inode *new_inode, struct dentry *new_dentry)
{
	// If not registered with enclave don't do anything.
	if(!system_ready()) return 0;
	return __trm_inode_rename(old_inode, old_dentry, new_inode, new_dentry);
}


/**
 * init_inode_smack - initialize an inode security blob
 * @inode: inode to extract the info from
 * @skp: a pointer to the Smack label entry to use in the blob
 *
 */
void init_inode_trm(struct inode *inode) { //, struct smack_known *skp
	struct inode_trm *itp = trm_inode(inode);
    itp->i_data = 23;
	mutex_init(&itp->lock);
}

int trm_inode_alloc_security(struct inode *inode) {
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
int trm_inode_init_security(struct inode *inode, struct inode *dir,
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



int trm_inode_setxattr(struct dentry *dentry, const char *name,
				       const void *value, size_t size, int flags)
{
    // struct inode *inode = d_backing_inode(dentry);
	// struct inode_security_struct *isec;
	// struct superblock_security_struct *sbsec;
	// struct common_audit_data ad;
	// u32 newsid, sid = current_sid();
	int rc = 0;
	char *pos;
    char *pathname = NULL;
	int pathname_len = 1024;

    

	// Check for security.citadel.install
	if (!strcmp(name, TRM_XATTR_INSTALL_NAME)) {
		pathname = kzalloc(pathname_len, GFP_KERNEL);
        pos = get_dentry_path(dentry, pathname, pathname_len);
        if (!IS_ERR(pos)) {
			printk(PFX "security.citadel.install for %s\n", pos);
			rc = (xattr_enclave_installation(value, size, dentry) ? -XATTR_REJECTED_SIGNAL : -XATTR_ACCEPTED_SIGNAL);
		} else {
			rc = -XATTR_REJECTED_SIGNAL;
		}
		kfree(pathname);
		return rc;
	}

	// Normal, non-security.citadel attribute.
	if (strcmp(name, TRM_XATTR_PREFIX)) {
		rc = cap_inode_setxattr(dentry, name, value, size, flags);
		if (rc)
			return rc;

		/* Not an attribute we recognize, so just check the
		   ordinary setattr permission. */
		return 0; //dentry_has_perm(current_cred(), dentry, FILE__SETATTR);
	}

	printk(PFX "trm_inode_setxattr() -- %s\n", name);
	// if (!selinux_initialized(&selinux_state))
	// 	return (inode_owner_or_capable(inode) ? 0 : -EPERM);

	// No-one can set this xattr apart from the kernel.
    return -EPERM; //(inode_owner_or_capable(inode) ? 0 : -EPERM);
}

void trm_inode_post_setxattr(struct dentry *dentry, const char *name,
					const void *value, size_t size,
					int flags)
{
	// struct inode *inode = d_backing_inode(dentry);
	// struct inode_security_struct *isec;
	// u32 newsid;
	// int rc;

	// if (strcmp(name, XATTR_NAME_SELINUX)) {
	// 	/* Not an attribute we recognize, so nothing to do. */
	// 	return;
	// }

	return;
}

int trm_inode_getxattr(struct dentry *dentry, const char *name)
{
	// const struct cred *cred = current_cred();
	return 0; //dentry_has_perm(cred, dentry, FILE__GETATTR);
}

int trm_inode_listxattr(struct dentry *dentry)
{
	// const struct cred *cred = current_cred();
	return 0; //dentry_has_perm(cred, dentry, FILE__GETATTR);
}

int trm_inode_removexattr(struct dentry *dentry, const char *name)
{
	if (strcmp(name, TRM_XATTR_PREFIX)) {
		int rc = cap_inode_removexattr(dentry, name);
		if (rc)
			return rc;

		/* Not an attribute we recognize, so just check the
		   ordinary setattr permission. */
		return 0; //dentry_has_perm(current_cred(), dentry, FILE__SETATTR);
	}

	/* No one is allowed to remove a SELinux security label.
	   You can change the label, but all data must be labeled. */
	return -EACCES;
}