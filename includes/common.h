

#ifndef _SECURITY_TRM_COMMON_H
#define _SECURITY_TRM_COMMON_H

#include <linux/lsm_hooks.h>
#include <linux/types.h>
#include <linux/cred.h>

#include "_citadel_shared.h"
#include "citadel.h"

#define PFX "LSM/Citadel: "
#define PFX_W KERN_WARNING PFX
#define PFX_E KERN_ERR PFX


typedef struct citadel_ticket_detail {
    unsigned char identifier[_CITADEL_IDENTIFIER_LENGTH];
    citadel_operation_t operation;
} citadel_ticket_detail_t;

typedef struct citadel_ticket {
    citadel_ticket_detail_t detail;
    ktime_t timestamp;
    struct citadel_ticket *next, *prev;
} citadel_ticket_t;


typedef struct citadel_task_data {
    bool in_realm;
    bool granted_pty;
    citadel_ticket_t *ticket_head;
    pid_t pid;
    unsigned char identifier[_CITADEL_IDENTIFIER_LENGTH];
    struct mutex lock;
} __randomize_layout citadel_task_data_t;

typedef struct citadel_inode_data {
    // Status flags.
    bool in_realm; // Boolean. TRUE if protected by Citadel.
    bool needs_xattr_update;
    bool checked_disk_xattr;
    bool is_socket;
    bool anonymous;

    unsigned char identifier[_CITADEL_IDENTIFIER_LENGTH];
    struct mutex lock;
} __randomize_layout citadel_inode_data_t;

typedef struct citadel_ipc_data {
    bool in_realm;
    unsigned char identifier[_CITADEL_IDENTIFIER_LENGTH];
} __randomize_layout citadel_ipc_data_t;


extern struct lsm_blob_sizes citadel_blob_sizes;

static inline citadel_inode_data_t *citadel_inode(const struct inode *inode) {
    if (unlikely(!inode) || unlikely(!inode->i_security)) return NULL;
	return inode->i_security + citadel_blob_sizes.lbs_inode;
}

static inline citadel_inode_data_t *citadel_dentry(const struct dentry *dentry) {
    if (unlikely(!dentry) || unlikely(!dentry->d_inode)) return NULL;
	return citadel_inode(d_real_inode(dentry));
}

static inline citadel_task_data_t *citadel_cred(const struct cred *cred) {
    if (unlikely(!cred)) return NULL;
	return cred->security + citadel_blob_sizes.lbs_cred;
}

static inline citadel_ipc_data_t *citadel_ipc(const struct kern_ipc_perm *ipc) {
    if (unlikely(!ipc)) return NULL;
	return ipc->security + citadel_blob_sizes.lbs_ipc;
}

#define printkc(format, args...)  \
    if (CITADEL_DEBUG) {                          \
        printk(PFX format, ## args);           \
    }

extern char *to_hexstring(unsigned char *buf, unsigned int len);
extern void *hexstring_to_bytes(char* hexstring);
extern char *get_path_for_dentry(struct dentry *dentry);
extern int   set_xattr_in_realm(struct dentry *dentry);
extern int   set_xattr_identifier(struct dentry *dentry, char *value, size_t len);
extern char *get_xattr_identifier(struct dentry *dentry, struct inode *inode);
extern void  inode_housekeeping(citadel_inode_data_t *i_trm, struct inode *inode);
extern void  dentry_housekeeping(citadel_inode_data_t *i_trm, struct dentry *dentry, struct inode *inode);
extern void  task_housekeeping(void);
extern int   can_access(struct inode *inode, citadel_operation_t operation);
extern bool  pty_check(struct inode *inode);

#endif  /* _SECURITY_TRM_CRYPTO_H */