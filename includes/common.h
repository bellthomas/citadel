

#ifndef _SECURITY_TRM_COMMON_H
#define _SECURITY_TRM_COMMON_H

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>

extern char* to_hexstring(unsigned char *buf, unsigned int len);
extern char* get_dentry_path(struct dentry *dentry, char * const buffer, const int buflen);

#endif  /* _SECURITY_TRM_CRYPTO_H */