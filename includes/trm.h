

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
#include <linux/dcache.h>


#include "_trm_shared.h"
#include "common.h"
#include "io.h"
#include "ticket_cache.h"
#include "crypto.h"
#include "inode.h"
#include "file.h"

extern int is_rsa_available(void);
extern int is_aes_available(void);

#endif /* _SECURITY_TRM_H */