
#include "../includes/common.h"

/* LSM's BLOB allocation. */
struct lsm_blob_sizes trm_blob_sizes __lsm_ro_after_init = {
	.lbs_cred = sizeof(struct task_trm),
	.lbs_file = 0, //sizeof(struct smack_known *),
	.lbs_inode = sizeof(struct inode_trm),
	.lbs_ipc = 0, //sizeof(struct smack_known *),
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


char *get_dentry_path(struct dentry *dentry, char * const buffer, const int buflen) {
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

// void find_dentry_root(struct dentry *dentry) {
// 	printk(PFX "Finding dentry root...\n");
// 	struct dentry *current_dentry = dentry;
// 	printk(PFX "%s\n", current_dentry->d_name->name);
// 	while(current_dentry->d_parent != NULL) {
// 		current_dentry = current_dentry->d_parent;
// 		printk(PFX "%s\n", current_dentry->d_name->name);
// 	}
// }




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
	return __internal_set_xattr(dentry, TRM_XATTR_REALM_NAME, NULL, 0);
}

int __internal_set_identifier(struct dentry *dentry, char *value, size_t len) {
	char *hex;
	int res;

	hex = to_hexstring(value, len);
	if (!hex) return -ENOMEM;
	res = __internal_set_xattr(dentry, TRM_XATTR_ID_NAME, hex, _TRM_IDENTIFIER_LENGTH * 2 + 1);
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

void* _hex_identifier_to_bytes(char* hexstring) {
	char* identifier = kmalloc(_TRM_IDENTIFIER_LENGTH, GFP_KERNEL);
	char* tracker = hexstring;
	size_t count;
	for(count = 0; count < _TRM_IDENTIFIER_LENGTH; count++) {
		sscanf(tracker, "%2hhx", &identifier[count]);
        tracker += 2;
	}
	return identifier;
}


void realm_housekeeping(struct inode_trm *i_trm, struct dentry *dentry) {
    if (!i_trm->in_realm) return;
    
    if (i_trm->needs_xattr_update) {
		printk(PFX "Need XATTR update\n");
        // Update xattrs.
    }
}


void global_housekeeping(struct inode_trm *i_trm, struct dentry *dentry) {
	int x;
	size_t identifier_length = 2 * _TRM_IDENTIFIER_LENGTH + 1;
	char *hex_identifier, *identifier, *h2;
	if (!i_trm->checked_disk_xattr) {
		i_trm->checked_disk_xattr = true;

		// Fetch identifier.
		hex_identifier = kzalloc(identifier_length, GFP_KERNEL);
		x = __vfs_getxattr(dentry, d_backing_inode(dentry), TRM_XATTR_ID_NAME, hex_identifier, identifier_length);
		if (x > 0) {
			printk(PFX "Loaded xattr from disk: %s\n", hex_identifier);
			identifier = _hex_identifier_to_bytes(hex_identifier);
			memcpy(i_trm->identifier, identifier, _TRM_IDENTIFIER_LENGTH);
			i_trm->in_realm = true;

			// ---
			h2 = to_hexstring(identifier, _TRM_IDENTIFIER_LENGTH);
			printk(PFX "Test conversion: %s\n", h2);
			kfree(h2);
			// ---

			kfree(identifier);
		}
		else {
			// No identifier, check for anonymous entity.
			x = __vfs_getxattr(dentry, d_backing_inode(dentry), TRM_XATTR_REALM_NAME, NULL, 0);
			i_trm->in_realm = (x > 0);
		}
		kfree(hex_identifier);
    }

	if (i_trm->in_realm) realm_housekeeping(i_trm, dentry);
}