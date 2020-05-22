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
#include <net/sock.h>

#include "../../includes/citadel.h"
#include "../../includes/inode.h"
#include "../../includes/payload_io.h"


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
	citadel_inode_data_t *itp;
	if (inode->i_ino < 2) return 0;  

	itp = trm_inode(inode);
	// printk(PFX "trm_inode_alloc_security for %ld\n", inode->i_ino);
    itp->in_realm = false;
	itp->needs_xattr_update = false;
	itp->checked_disk_xattr = false;
	itp->is_socket = false;
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
	citadel_inode_data_t *new_inode_data = trm_inode(inode);
	citadel_inode_data_t *parent_inode_data = trm_inode(dir);

	// Hierarchical subsumption.
	if (parent_inode_data->in_realm && !new_inode_data->in_realm) {
		printk(PFX "trm_inode_init_security setting child (%ld)\n", inode->i_ino);
		new_inode_data->in_realm = true;
		new_inode_data->needs_xattr_update = true;
	}

	return -EOPNOTSUPP; // We don't use security attributes here.
}


/*
 *	Check permission before accessing an inode.  This hook is called by the
 *	existing Linux permission function, so a security module can use it to
 *	provide additional checking for existing Linux permission checks.
 *	Notice that this hook is called when a file is opened (as well as many
 *	other operations), whereas the file_security_ops permission hook is
 *	called when the actual read/write operations are performed.
 *	@inode contains the inode structure to check.
 *	@mask contains the permission mask.
 *	Return 0 if permission is granted.
 */
int trm_inode_permission(struct inode *inode, int mask) {
	citadel_inode_data_t *inode_data = trm_inode(inode);
	task_housekeeping();
	if (inode_data && inode_data->in_realm) {
		return can_access(inode_data);
	} 
	return 0;
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
	// char *hex_id, *identifier;
    // char *pathname = NULL;
	// int res;
	// struct inode *inode = d_backing_inode(old_dentry);
	citadel_inode_data_t *old_inode_trm = trm_dentry(old_dentry);

	// inode_housekeeping(old_inode_trm, old_dentry);

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


int trm_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc) {
	citadel_inode_data_t *inode_data = trm_inode(inode);
	struct socket *sock;
	struct inode *ip = (struct inode *)inode;

	// Verify that inode belongs to SockFS.
	if (ip->i_sb->s_magic != SOCKFS_MAGIC)
		return -EOPNOTSUPP;

	// Only use for sockets, files' xattrs are served from VFS.
	if (inode_data && inode_data->in_realm && inode_data->is_socket) {
		// This is a protected socket.

		if (strncmp(name, _CITADEL_XATTR_NS_TAG_IN_REALM, sizeof(_CITADEL_XATTR_NS_TAG_IN_REALM)) == 0) {
			return 0;
		}

		if (strncmp(name, _CITADEL_XATTR_NS_TAG_IDENTIFIER, sizeof(_CITADEL_XATTR_NS_TAG_IDENTIFIER)) == 0) {
			// This is security.citadel.identifier
			if (alloc) {
				*buffer = to_hexstring(inode_data->identifier, _TRM_IDENTIFIER_LENGTH);
				if (*buffer == NULL)
					return -ENOMEM;
			}
			return 2 * _TRM_IDENTIFIER_LENGTH + 1;
		}
	}
	
	return -EOPNOTSUPP;
}

int trm_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size) {
	const int len = sizeof(_TRM_XATTR_IN_REALM);
	if (buffer && len <= buffer_size)
		memcpy(buffer, _TRM_XATTR_IN_REALM, len);
	return 0;
}

void trm_d_instantiate(struct dentry *dentry, struct inode *inode) {
	citadel_inode_data_t *inode_data = trm_inode(inode);
	if(inode_data->in_realm) {
		if (!inode_data->is_socket) {
			dentry->d_inode = inode;
			realm_housekeeping(inode_data, dentry);
			dentry->d_inode = NULL;
		}
		printk(PFX "trm_d_instantiate (in_realm: %d, %ld, socket: %d)\n", inode_data->in_realm, inode->i_ino, inode_data->is_socket);
	}
}




/* Region: xattrs */
int trm_inode_setxattr(struct dentry *dentry, const char *name,
				       const void *value, size_t size, int flags)
{
	int rc = 0;

	// Check for security.citadel.install
	if (!strcmp(name, TRM_XATTR_INSTALL_NAME)) {
		if(system_ready())
			rc = xattr_enclave_installation(value, size, dentry) ? -XATTR_REJECTED_SIGNAL : -XATTR_ACCEPTED_SIGNAL;
		else
			rc = -ECANCELED; // Can't process this operation yet.
	
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

void trm_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	citadel_inode_data_t *inode_data = trm_dentry(dentry);

	if (inode_data) {
		// Do housekeeping.
		inode_housekeeping(inode_data, dentry);

		if (inode_data->in_realm) {
			// Log for debug.
			printk(PFX "trm_inode_post_setxattr for PID %d (in_realm)\n", current->pid);
		}
	}
	return;
}

int trm_inode_getxattr(struct dentry *dentry, const char *name)
{
	citadel_inode_data_t *inode_data = trm_dentry(dentry);
	if(inode_data)
		inode_housekeeping(inode_data, dentry);
	return 0;
}
int trm_inode_listxattr(struct dentry *dentry) {
	citadel_inode_data_t *current_inode_trm = trm_dentry(dentry);
	if(current_inode_trm)
		inode_housekeeping(current_inode_trm, dentry);
	return 0;
}

int trm_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct task_struct *task = current;
	citadel_inode_data_t *current_inode_trm = trm_dentry(dentry);
	if(current_inode_trm)
		inode_housekeeping(current_inode_trm, dentry);

	if (strncmp(name, TRM_XATTR_PREFIX, strlen(TRM_XATTR_PREFIX))) {
		return cap_inode_removexattr(dentry, name);
	}

	printk(PFX "trm_inode_removexattr from PID %d\n", task->pid);

	/* No one is allowed to remove a Citadel security label. */
	return -EACCES;
}