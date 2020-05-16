

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
#include <linux/semaphore.h>

#include "_trm_shared.h"
#include "common.h"
#include "crypto.h"

extern int system_ready(void);
extern void* generate_challenge(size_t *len);
extern void process_challenge_response(void *response, size_t response_len);
extern void* generate_update(size_t *len);
extern void process_received_update(void *update, size_t update_len);
extern int xattr_enclave_installation(const void *value, size_t size, struct dentry *dentry);
extern void* generate_ptoken(size_t *len);

#endif /* _SECURITY_TRM_ENCL_COMMS_H */