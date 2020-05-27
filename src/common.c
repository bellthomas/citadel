#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/magic.h>

#include "../includes/citadel.h"
#include "../includes/common.h"
#include "../includes/ticket_cache.h"
#include "../includes/payload_io.h"


/* LSM's BLOB allocation. */
struct lsm_blob_sizes citadel_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(citadel_task_data_t),
	.lbs_file = 0, //sizeof(struct smack_known *),
	.lbs_inode = sizeof(citadel_inode_data_t),
	.lbs_ipc = sizeof(citadel_ipc_data_t),
	.lbs_msg_msg = 0 //sizeof(struct smack_known *),
};


char* to_hexstring(unsigned char *buf, unsigned int len) {
    char   *out;
	size_t  i;

    if (buf == NULL || len == 0) return NULL;

    out = kmalloc(2*len+1, GFP_KERNEL);
    for (i=0; i<len; i++) {
		out[i*2]   = "0123456789ABCDEF"[buf[i] >> 4];
		out[i*2+1] = "0123456789ABCDEF"[buf[i] & 0x0F];
	}
    out[len*2] = '\0';
    return out;
}



// void find_dentry_root(struct dentry *dentry) {
// 	printk(PFX "Finding dentry root...\n");
// 	struct dentry *current_dentry = dentry;
// 	printk(PFX "%s\n", current_dentry->d_name->name);
// 	while(current_dentry->d_parent != NULL) {
// 		current_dentry = current_dentry->d_parent;
// 		printk(PFX "%s\n", current_dentry->d_name->name);
// 	}
// }

// static char *tomoyo_get_dentry_path(struct dentry *dentry, char * const buffer,
// 				    const int buflen)
// {
// 	char *pos = ERR_PTR(-ENOMEM);

// 	if (buflen >= 256) {
// 		pos = dentry_path_raw(dentry, buffer, buflen - 1);
// 		if (!IS_ERR(pos) && *pos == '/' && pos[1]) {
// 			struct inode *inode = d_backing_inode(dentry);

// 			if (inode && S_ISDIR(inode->i_mode)) {
// 				buffer[buflen - 2] = '/';
// 				buffer[buflen - 1] = '\0';
// 			}
// 		}
// 	}
// 	return pos;
// }

/**
 * tomoyo_get_local_path - Get the path of a dentry.
 *
 * @dentry: Pointer to "struct dentry".
 * @buffer: Pointer to buffer to return value in.
 * @buflen: Sizeof @buffer.
 *
 * Returns the buffer on success, an error code otherwise.
 */
// static char *tomoyo_get_local_path(struct dentry *dentry, char * const buffer,
// 				   const int buflen)
// {
// 	struct super_block *sb = dentry->d_sb;
// 	char *pos = tomoyo_get_dentry_path(dentry, buffer, buflen);

// 	if (IS_ERR(pos))
// 		return pos;
// 	/* Convert from $PID to self if $PID is current thread. */
// 	if (sb->s_magic == PROC_SUPER_MAGIC && *pos == '/') {
// 		char *ep;
// 		const pid_t pid = (pid_t) simple_strtoul(pos + 1, &ep, 10);

// 		if (*ep == '/' && pid && pid ==
// 		    task_tgid_nr_ns(current, sb->s_fs_info)) {
// 			pos = ep - 5;
// 			if (pos < buffer)
// 				goto out;
// 			memmove(pos, "/self", 5);
// 		}
// 		goto prepend_filesystem_name;
// 	}
// 	/* Use filesystem name for unnamed devices. */
// 	if (!MAJOR(sb->s_dev))
// 		goto prepend_filesystem_name;
// 	{
// 		struct inode *inode = d_backing_inode(sb->s_root);

// 		/*
// 		 * Use filesystem name if filesystem does not support rename()
// 		 * operation.
// 		 */
// 		if (!inode->i_op->rename)
// 			goto prepend_filesystem_name;
// 	}
// 	/* Prepend device name. */
// 	{
// 		char name[64];
// 		int name_len;
// 		const dev_t dev = sb->s_dev;

// 		name[sizeof(name) - 1] = '\0';
// 		snprintf(name, sizeof(name) - 1, "dev(%u,%u):", MAJOR(dev),
// 			 MINOR(dev));
// 		name_len = strlen(name);
// 		pos -= name_len;
// 		if (pos < buffer)
// 			goto out;
// 		memmove(pos, name, name_len);
// 		return pos;
// 	}
// 	/* Prepend filesystem name. */
// prepend_filesystem_name:
// 	{
// 		const char *name = sb->s_type->name;
// 		const int name_len = strlen(name);

// 		pos -= name_len + 1;
// 		if (pos < buffer)
// 			goto out;
// 		memmove(pos, name, name_len);
// 		pos[name_len] = ':';
// 	}
// 	return pos;
// out:
// 	return ERR_PTR(-ENOMEM);
// }


char *get_path_for_dentry(struct dentry *dentry) {
	// char *pos = NULL;
    // char *pathname = NULL;
	// size_t pathname_len = 2048;
	// struct inode *d_inode;

	// pathname = kzalloc(pathname_len, GFP_NOFS);
	// pos = pathname;
	// if(pathname) {
	// 	pos = dentry_path_raw(dentry, pathname, pathname_len - 1);
	// 	if (!IS_ERR(pos)) {
	// 		if(*pos == '/' && pos[1]) {
	// 			printk(PFX "Doing inode things\n");
	// 			d_inode = d_backing_inode(dentry);
	// 			if (d_inode) {
	// 				printk(PFX "Got inode\n");
	// 				if(S_ISDIR(d_inode->i_mode)) {
	// 					printk(PFX "Is directory\n");
	// 					pathname[pathname_len - 2] = '/';
	// 					pathname[pathname_len - 1] = '\0';
	// 				}
	// 			}
	// 		}

	// 		printk(PFX "%p %p\n", pathname, pos);
	// 		return pathname;
	// 	} else {
	// 		printk(PFX "Aborting get_path_for_dentry()\n");
	// 		return pathname; // Empty buffer. 3101233312 - 2936675473
	// 	}
	// }
	return NULL;
	// pos = tomoyo_get_local_path(dentry, pathname, pathname_len);
	// if (IS_ERR(pos)) {
	// 	return pathname;
	// }

	// return pos;
}


/*
 * Internal.
 * Raw call to __vfs_setxattr_noperm. Requires caller to organise dentry locking.
 * Returns error code of the VFS call.
 */
int __internal_set_xattr(struct dentry *dentry, const char *name, char *value, size_t len) {
	int res;
	// need to lock inode->i_rwsem
    // down_write(&(dentry->d_inode->i_rwsem));
    res = __vfs_setxattr_noperm(dentry, name, (const void*)value, len, 0);
	// up_write(&(dentry->d_inode->i_rwsem));
	return res;
}


int __internal_set_in_realm(struct dentry *dentry) {
	return __internal_set_xattr(dentry, _CITADEL_XATTR_IN_REALM, NULL, 0);
}

int __internal_set_identifier(struct dentry *dentry, char *value, size_t len) {
	char *hex;
	int res;

	hex = to_hexstring(value, len);
	if (!hex) return -ENOMEM;
	res = __internal_set_xattr(dentry, _CITADEL_XATTR_IDENTIFIER, hex, _CITADEL_IDENTIFIER_LENGTH * 2 + 1);
	kfree(hex);
	return res;
}

int set_xattr_in_realm(struct dentry *dentry) {
	int res;
	// down_write(&(dentry->d_inode->i_rwsem));
	res = __internal_set_in_realm(dentry);
	// up_write(&(dentry->d_inode->i_rwsem));
	return res;
}

int set_xattr_identifier(struct dentry *dentry, char *value, size_t len) {
	int res_a, res_b;
	// down_write(&(dentry->d_inode->i_rwsem));
	res_a = __internal_set_identifier(dentry, value, len);
	res_b = __internal_set_in_realm(dentry);
	// up_write(&(dentry->d_inode->i_rwsem));
	return (res_a < res_b) ? res_a : res_b;
}

void* hexstring_to_bytes(char* hexstring) {
	size_t i, j;
	size_t len = strlen(hexstring);
	size_t final_len = len / 2;
	unsigned char* identifier; 

    if(len % 2 != 0) return NULL;

	identifier = (unsigned char*) kmalloc(final_len, GFP_KERNEL);
    for (i = 0, j = 0; j < final_len; i += 2, j++) {
        identifier[j] = (hexstring[i] % 32 + 9) % 25 * 16 + (hexstring[i+1] % 32 + 9) % 25;
	}
	return identifier;
}

char *get_xattr_identifier(struct dentry *dentry, struct inode *inode) {
	int x;
	char *hex_identifier, *identifier;
	size_t identifier_length = _CITADEL_ENCODED_IDENTIFIER_LENGTH;
	
	hex_identifier = kzalloc(identifier_length, GFP_KERNEL);
	x = __vfs_getxattr(dentry, inode, _CITADEL_XATTR_IDENTIFIER, hex_identifier, identifier_length);
	if (x > 0) {
		identifier = hexstring_to_bytes(hex_identifier);
	} else {
		identifier = NULL;
	}

	kfree(hex_identifier);
	return identifier;
}

void task_housekeeping(void) {
	citadel_task_data_t *cred = citadel_cred(current_cred());	
	if (current->pid > 1) {
		if (cred->pid == 1) cred->pid = current->pid;
		// else if (current->pid != cred->pid) printk(PFX "PID forging detected (task_housekeeping, %d != %d (parent %d))\n", current->pid, cred->pid, current->parent->pid); 
		check_ticket_cache();
	}
}

void inode_housekeeping(citadel_inode_data_t *inode_data, struct inode *inode) {
	// char *pipe_id;
	citadel_task_data_t *task_data = citadel_cred(current_cred());
	if (unlikely(!inode) || unlikely(!inode_data) || inode->i_ino < 2) return;

	if (inode->i_sb->s_magic == PIPEFS_MAGIC) { // !S_ISFIFO(inode->i_mode)

		// This is an unnamed pipe.
		if (inode_data->anonymous && task_data && task_data->in_realm) {
			// Assume this pipe has just been created.
			memcpy(inode_data->identifier, task_data->identifier, sizeof(inode_data->identifier));
			inode_data->anonymous = false;
			inode_data->checked_disk_xattr = true;
			inode_data->needs_xattr_update = false;

			// pipe_id = to_hexstring(inode_data->identifier, _CITADEL_IDENTIFIER_LENGTH);
			// printk(PFX "Tagged PipeFS inode (%ld) for PID %d\n", inode->i_ino, current->pid);
			// kfree(pipe_id);
		}
	}
	// else if (S_ISFIFO(inode->i_mode)) {
	// 	printk(PFX "Got named pipe!\n");
	// }
}

void dentry_housekeeping(citadel_inode_data_t *inode_data, struct dentry *dentry, struct inode *inode) {
	int read, res;
	char *identifier;
	// struct inode *ino = d_backing_inode(dentry);

	// Abort if invalid.
	if (unlikely(!inode_data) || unlikely(!dentry)) return;
	if (likely(inode)) inode_housekeeping(inode_data, inode);

	if (!inode_data->checked_disk_xattr && !inode_data->is_socket) {
		inode_data->checked_disk_xattr = true;

		// Fetch in_realm.
		read = __vfs_getxattr(dentry, inode, _CITADEL_XATTR_IN_REALM, NULL, 0);

		// If xattr doesn't exists read will equal -1.
		if (unlikely(read >= 0)) {
			inode_data->in_realm = true;
			identifier = get_xattr_identifier(dentry, inode);
			if (identifier) {
				memcpy(inode_data->identifier, identifier, _CITADEL_IDENTIFIER_LENGTH);
				kfree(identifier);
			} 
		}
    }

	if (unlikely(inode_data->in_realm)) {
		if (inode_data->needs_xattr_update && !inode_data->is_socket) {
			inode_data->needs_xattr_update = false;
			res = set_xattr_in_realm(dentry);
			printk(PFX "realm_housekeeping -> set xattr (%d)\n", res);
			// TODO support setting identifier
		}
	}
}

bool pty_check(struct inode *inode) {
	citadel_task_data_t *cred = citadel_cred(current_cred());
	return ((inode->i_sb->s_magic == DEVPTS_SUPER_MAGIC) && cred->granted_pty);
}


/*
   The following POSIX macros are defined to check the file type using the st_mode field:	
       S_ISREG(m)  is it a regular file?
       S_ISDIR(m)  directory?
       S_ISCHR(m)  character device?
       S_ISBLK(m)  block device?
       S_ISFIFO(m) FIFO (named pipe)?
       S_ISLNK(m)  symbolic link? (Not in POSIX.1-1996.)
       S_ISSOCK(m) socket? (Not in POSIX.1-1996.)
*/
int can_access(struct inode *inode, citadel_operation_t operation) {
	ktime_t tracker;
	size_t tmp;
	bool found = false;
	citadel_ticket_t *current_ticket;
	citadel_inode_data_t *inode_data = citadel_inode(inode);
	citadel_task_data_t *cred = citadel_cred(current_cred());

	// Invalid, allow.
	if (unlikely(!inode_data) || unlikely(!inode)) return 0;
	if (inode->i_ino < 2) return 0;
	if (!inode_data->in_realm && !cred->in_realm) return 0;

	// Check for forged PID.
	// if (cred->pid > 1 && current->pid != cred->pid) {
	// 	printk(PFX "forged PID! %d vs %d\n", current->pid, cred->pid);
	// }

	// Allow directory traversing, SockFS, SysFS, SecurityFS.
	if (S_ISDIR(inode->i_mode)) return 0;
	if (inode->i_sb->s_magic == SOCKFS_MAGIC) return 0;
	else if (inode->i_sb->s_magic == SYSFS_MAGIC) return 0;
	else if (inode->i_sb->s_magic == SECURITYFS_MAGIC) return 0;

	else if (inode->i_sb->s_magic == PIPEFS_MAGIC) { // && !S_ISFIFO(inode->i_mode)
		// All processes can always access their own unnamed pipes.
		printk(PFX "Checking unnamed pipe...\n");
		found = true;
		for (tmp = 0; tmp < _CITADEL_IDENTIFIER_LENGTH; tmp++) {
			if (inode_data->identifier[tmp] != cred->identifier[tmp]) {
				found = false;
				break;
			}
		}
		if (unlikely(found)) return 0;
	}
			
		
	// All processes can access public Citadel resources.
	// Key: 0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF
	found = true;
	for (tmp = 0; tmp < _CITADEL_IDENTIFIER_LENGTH; tmp++) {
		if (inode_data->identifier[tmp] != 0xFF) {
			found = false;
			break;
		}
	}
	if (unlikely(found)) return 0;

	// Citadel can access all objects.
	if (current->pid == citadel_pid()) return 0;

	// Check for exceptional PTY access.
	if (pty_check(inode)) return 0;

	// No tickets, no access.
	if (!cred || !cred->ticket_head) {
		printk(PFX "Rejecting PID %d access to object (magic: %ld, ino: %ld).\n", current->pid, inode->i_sb->s_magic, inode->i_ino);
		return -EACCES;
	}

	// Short circuit if node is anonymous.
	if (inode_data->anonymous) {
		printk(PFX "Rejected PID %d access to anonymous inode (%ld)\n", current->pid, inode->i_ino);
		return -EACCES;
	}

	// Let's see if the process has the correct ticket.
	current_ticket = cred->ticket_head;
	tracker = 0;
	while (current_ticket->timestamp > tracker && !found) {

		// Check if this ticket allows access.
		found = true;
		for (tmp = 0; tmp < _CITADEL_IDENTIFIER_LENGTH; tmp++) {
			if (current_ticket->detail.identifier[tmp] != inode_data->identifier[tmp]) {
				found = false;
				break;
			}
		}

		// Check if this enables the requested operation.
		if (found && (current_ticket->detail.operation & operation) == 0)
			found = false;

		if (!found) {
			tracker = current_ticket->timestamp;
			current_ticket = current_ticket->next;
		}
	}

	if (found) {
		// Found a ticket relating to this object.
		printk(PFX "Allowing PID %d access to object (ino: %ld, cred: %d).\n", current->pid, inode->i_ino, cred->pid);
		if (inode_data->in_realm) cred->in_realm = true;
		if (cred->in_realm) inode_data->in_realm = true;
		return 0;
	}

	printk(PFX "Rejecting PID %d access to object (magic: %ld, ino: %ld).\n", current->pid, inode->i_sb->s_magic, inode->i_ino);
	return -EACCES;
}