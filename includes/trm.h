

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

#include "common.h"

#define PFX "LSM/TRM: "

struct trm_request {
    int flags;
};

#endif  /* _SECURITY_TRM_H */