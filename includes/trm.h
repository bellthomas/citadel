

#ifndef _SECURITY_TRM_H
#define _SECURITY_TRM_H

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

#include "common.h"
#include "io.h"
#include "ticket_cache.h"
#include "crypto.h"
#include "inode.h"

#define PFX "LSM/TRM: "
#define PFX_W KERN_WARNING PFX
#define PFX_E KERN_ERR PFX
#define TRM_XATTR_PREFIX "security.citadel"
#define TRM_XATTR_ID_NAME TRM_XATTR_PREFIX ".identifier"
#define TRM_XATTR_REALM_NAME TRM_XATTR_PREFIX ".in_realm"
#define TRM_XATTR_INSTALL_NAME TRM_XATTR_PREFIX ".install"


struct task_trm {
    uint8_t t_data;
};

struct inode_trm {
    uint8_t i_data;
    struct mutex lock;
};

extern struct lsm_blob_sizes trm_blob_sizes __lsm_ro_after_init;

static inline struct inode_trm *trm_inode(const struct inode *inode) {
	return inode->i_security + trm_blob_sizes.lbs_inode;
}

static inline struct task_trm *trm_cred(const struct cred *cred) {
	return cred->security + trm_blob_sizes.lbs_cred;
}

extern int is_rsa_available(void);
extern int is_aes_available(void);

#endif /* _SECURITY_TRM_H */