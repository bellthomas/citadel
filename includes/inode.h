#ifndef _SECURITY_TRM_LSM_INODE_H
#define _SECURITY_TRM_LSM_INODE_H

#include "trm.h"

extern int trm_inode_alloc_security(struct inode *inode);
extern int trm_inode_init_security(struct inode *inode, struct inode *dir, const struct qstr *qstr, const char **name, void **value, size_t *len);
extern int trm_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry);
extern int trm_inode_rename(struct inode *old_inode, struct dentry *old_dentry, struct inode *new_inode, struct dentry *new_dentry);

extern int trm_inode_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
extern void trm_inode_post_setxattr(struct dentry *dentry, const char *name, const void *value, size_t size, int flags);
extern int trm_inode_removexattr(struct dentry *dentry, const char *name);

#endif  /* _SECURITY_TRM_LSM_INODE_H */