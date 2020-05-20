

#ifndef _SECURITY_TRM_COMMON_H
#define _SECURITY_TRM_COMMON_H

#include <linux/lsm_hooks.h>

#include "_citadel_shared.h"
#include "citadel.h"

#define PFX "LSM/Citadel: "
#define PFX_W KERN_WARNING PFX
#define PFX_E KERN_ERR PFX
#define TRM_XATTR_PREFIX XATTR_SECURITY_PREFIX "citadel."
#define TRM_XATTR_ID_NAME TRM_XATTR_PREFIX "identifier"
#define TRM_XATTR_REALM_NAME TRM_XATTR_PREFIX "in_realm"
#define TRM_XATTR_INSTALL_NAME TRM_XATTR_PREFIX "install"


typedef struct citadel_ticket_detail {
    unsigned char identifier[_TRM_IDENTIFIER_LENGTH];
    citadel_operation_t operation;
} citadel_ticket_detail_t;

typedef struct citadel_ticket {
    citadel_ticket_detail_t detail;
    ktime_t timestamp;
    struct citadel_ticket *next, *prev;
} citadel_ticket_t;


typedef struct citadel_task_data {
    uint8_t t_data;
    citadel_ticket_t *ticket_head;
} __randomize_layout citadel_task_data_t;

typedef struct citadel_inode_data {
    // Status flags.
    bool in_realm; // Boolean. TRUE if protected by Citadel.
    bool needs_xattr_update;
    bool checked_disk_xattr;

    unsigned char identifier[_TRM_IDENTIFIER_LENGTH];
    struct mutex lock;

    uint8_t data;
} __randomize_layout citadel_inode_data_t;


extern struct lsm_blob_sizes citadel_blob_sizes;

static inline citadel_inode_data_t *trm_inode(const struct inode *inode) {
    if (unlikely(!inode) || unlikely(!inode->i_security)) return NULL;
	return inode->i_security + citadel_blob_sizes.lbs_inode;
}

static inline citadel_inode_data_t *trm_dentry(const struct dentry *dentry) {
    if (unlikely(!dentry) || unlikely(!dentry->d_inode)) return NULL;
	return trm_inode(d_real_inode(dentry));
}

static inline citadel_task_data_t *trm_cred(const struct cred *cred) {
    if (unlikely(!cred)) return NULL;
	return cred->security + citadel_blob_sizes.lbs_cred;
}

extern char *to_hexstring(unsigned char *buf, unsigned int len);
extern char *get_path_for_dentry(struct dentry *dentry);
extern int   set_xattr_in_realm(struct dentry *dentry);
extern int   set_xattr_identifier(struct dentry *dentry, char *value, size_t len);
extern char *get_xattr_identifier(struct dentry *dentry);
extern void  realm_housekeeping(citadel_inode_data_t *i_trm, struct dentry *dentry);
extern void  inode_housekeeping(citadel_inode_data_t *i_trm, struct dentry *dentry);
extern void  task_housekeeping(void);

#endif  /* _SECURITY_TRM_CRYPTO_H */