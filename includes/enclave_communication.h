

#ifndef _SECURITY_TRM_ENCL_COMMS_H
#define _SECURITY_TRM_ENCL_COMMS_H

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
#include "crypto.h"

static const unsigned char challenge_signature[8] = { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };

// Needs to be 256 bytes.
struct trm_challenge {
    unsigned char signature[8];
    unsigned char challenge[32];
    unsigned char name[40];
    unsigned char key[128];
    pid_t pid;
};

extern void* generate_challenge(size_t *len);


#endif /* _SECURITY_TRM_ENCL_COMMS_H */