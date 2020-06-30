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
#include "../../includes/shm_tracking.h"


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

	itp = citadel_inode(inode);
	// printkc("trm_inode_alloc_security for %ld\n", inode->i_ino);
    itp->in_realm = false;
	itp->needs_xattr_update = false;
	itp->checked_disk_xattr = false;
	itp->is_socket = false;
	itp->anonymous = true;
	mutex_init(&itp->lock);

	inode_housekeeping(itp, inode);
	return 0;
}


/*
 *	@inode contains the inode structure.
 *	Deallocate the inode security structure and set @inode->i_security to
 *	NULL.
 */
void trm_inode_free_security(struct inode *inode) {
	citadel_inode_data_t *itp;
	if (inode->i_ino < 2) return;  

	itp = citadel_inode(inode);
	mutex_destroy(&itp->lock);
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
	citadel_inode_data_t *new_inode_data = citadel_inode(inode);
	citadel_inode_data_t *parent_inode_data = citadel_inode(dir);
	citadel_task_data_t *task_data = citadel_cred(current_cred());

	// Hierarchical subsumption.
	if ((parent_inode_data->in_realm || task_data->in_realm) && !new_inode_data->in_realm) {
		printkc("trm_inode_init_security setting child (%ld) [%d,%d]\n", inode->i_ino, parent_inode_data->in_realm, task_data->in_realm);
		new_inode_data->in_realm = true;
		new_inode_data->needs_xattr_update = true;
		if (task_data->in_realm) {
			printkc("New inode is being quietly granted parent identifier\n");
			new_inode_data->anonymous = false;
			memcpy(new_inode_data->identifier, task_data->identifier, _CITADEL_IDENTIFIER_LENGTH);
		}
	}

	inode_housekeeping(new_inode_data, inode);
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
	citadel_inode_data_t *inode_data = citadel_inode(inode);
	citadel_task_data_t *task_data = citadel_cred(current_cred());
	task_housekeeping();
	inode_housekeeping(inode_data, inode);
	if (inode_data && (inode_data->in_realm || task_data->in_realm)) {
		return can_access(inode, CITADEL_OP_OPEN);
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
	citadel_inode_data_t *old_inode_trm = citadel_dentry(old_dentry);

	// dentry_housekeeping(old_inode_trm, old_dentry);

	// Copy metadata to the new inode link.
	if (old_inode_trm) {
		if (old_inode_trm->in_realm) {
			if (new_dentry->d_inode) {
				printkc("trm_inode_link, in realm and got new inode\n");
			} else {
				printkc("trm_inode_link, in realm and NOT got new inode\n");
			}

			if (old_dentry->d_inode) {
				printkc("trm_inode_link, in realm and got old inode\n");
			} else {
				printkc("trm_inode_link, in realm and NOT got old inode\n");
			}
		}
	} else {
		printkc("no old_inode_trm\n");
	}

	return 0;
}


int trm_inode_getsecurity(struct inode *inode, const char *name, void **buffer, bool alloc) {
	citadel_inode_data_t *inode_data = citadel_inode(inode);
	struct inode *ip = (struct inode *)inode;
	char *key;

	// SHM tracking.
	if (ip->i_sb->s_magic == SECURITYFS_MAGIC) {

		if (strncmp(name, _CITADEL_XATTR_NS_TAG_SHM ".", sizeof(_CITADEL_XATTR_NS_TAG_SHM)) == 0) {
			// security.citadel.shm.*
			key = (char*)name + sizeof(_CITADEL_XATTR_NS_TAG_SHM);
			return get_shmid_inhabitants(key, alloc, buffer);
		}

		return -EOPNOTSUPP;
	}

	// Only use for sockets, files' xattrs are served from VFS.
	// Verify that inode belongs to SockFS.
	if (ip->i_sb->s_magic != SOCKFS_MAGIC)
		return -EOPNOTSUPP;

	if (inode_data && inode_data->in_realm && inode_data->is_socket) {
		// This is a protected socket.

		// This is security.citadel.in_realm
		if (strncmp(name, _CITADEL_XATTR_NS_TAG_IN_REALM, sizeof(_CITADEL_XATTR_NS_TAG_IN_REALM)) == 0) {
			return 0;
		}

		// This is security.citadel.identifier
		if (strncmp(name, _CITADEL_XATTR_NS_TAG_IDENTIFIER, sizeof(_CITADEL_XATTR_NS_TAG_IDENTIFIER)) == 0) {
			if (alloc) {
				*buffer = to_hexstring(inode_data->identifier, _CITADEL_IDENTIFIER_LENGTH);
				if (*buffer == NULL) return -ENOMEM;
			}
			return _CITADEL_ENCODED_IDENTIFIER_LENGTH;
		}
	}
	
	return -EOPNOTSUPP;
}

int trm_inode_listsecurity(struct inode *inode, char *buffer, size_t buffer_size) {
	const int len = sizeof(_CITADEL_XATTR_IN_REALM);
	if (buffer && len <= buffer_size)
		memcpy(buffer, _CITADEL_XATTR_IN_REALM, len);
	return 0;
}

void trm_d_instantiate(struct dentry *dentry, struct inode *inode) {
	citadel_inode_data_t *inode_data = citadel_inode(inode);
	struct inode *current_inode = NULL;
	if (inode_data) {
		current_inode = dentry->d_inode;
		dentry->d_inode = inode;
		dentry_housekeeping(inode_data, dentry, inode);
		dentry->d_inode = current_inode;
	}

	// if(inode_data && inode_data->in_realm && !inode_data->is_socket) {
	// 	dentry->d_inode = inode;
	// 	dentry_housekeeping(inode_data, dentry);
	// 	dentry->d_inode = NULL;
	// } else {
	// 	inode_housekeeping(inode_data, inode);
	// }
}




/* Region: xattrs */
int trm_inode_setxattr(struct dentry *dentry, const char *name,
				       const void *value, size_t size, int flags)
{
	int rc = 0;

	// Check for security.citadel.install
	if (!strcmp(name, _CITADEL_XATTR_INSTALL)) {
		if(system_ready())
			rc = xattr_enclave_installation(value, size, dentry) ? -_CITADEL_XATTR_REJECTED_SIGNAL : -_CITADEL_XATTR_ACCEPTED_SIGNAL;
		else
			rc = -ECANCELED; // Can't process this operation yet.
	
		return rc;
	}

	// Normal, non-security.citadel.* attribute.
	if (strncmp(name, _CITADEL_XATTR_ROOT, strlen(_CITADEL_XATTR_ROOT))) {
		return cap_inode_setxattr(dentry, name, value, size, flags);
	}

	// No-one can set this xattr apart from the kernel.
	printkc("Rejected trm_inode_setxattr() -- %s\n", name);
    return -EPERM; //(inode_owner_or_capable(inode) ? 0 : -EPERM);
}

void trm_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags)
{
	citadel_inode_data_t *inode_data = citadel_dentry(dentry);

	if (inode_data) {
		// Do housekeeping.
		dentry_housekeeping(inode_data, dentry, d_backing_inode(dentry));

		// if (inode_data->in_realm) {
		// 	// Log for debug.
		// 	printkc("trm_inode_post_setxattr for PID %d (in_realm)\n", current->pid);
		// }
	}
	return;
}

int trm_inode_getxattr(struct dentry *dentry, const char *name)
{
	citadel_inode_data_t *inode_data = citadel_dentry(dentry);
	if(inode_data)
		dentry_housekeeping(inode_data, dentry, d_backing_inode(dentry));
	return 0;
}
int trm_inode_listxattr(struct dentry *dentry) {
	citadel_inode_data_t *current_inode_trm = citadel_dentry(dentry);
	if(current_inode_trm)
		dentry_housekeeping(current_inode_trm, dentry, d_backing_inode(dentry));
	return 0;
}

int trm_inode_removexattr(struct dentry *dentry, const char *name)
{
	struct task_struct *task = current;
	citadel_inode_data_t *current_inode_trm = citadel_dentry(dentry);
	if(current_inode_trm)
		dentry_housekeeping(current_inode_trm, dentry, d_backing_inode(dentry));

	if (strncmp(name, _CITADEL_XATTR_ROOT, strlen(_CITADEL_XATTR_ROOT))) {
		return cap_inode_removexattr(dentry, name);
	}

	printkc("trm_inode_removexattr from PID %d\n", task->pid);

	/* No one is allowed to remove a Citadel security label. */
	return -EACCES;
}