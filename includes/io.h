

#ifndef _SECURITY_TRM_IO_H
#define _SECURITY_TRM_IO_H

#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>

#include "citadel.h"

#define CHALLENGE_MAX_SIZE 256 // Using 2048-bit RSA.

// io.c
extern ssize_t challenge_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
extern ssize_t challenge_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos);
extern ssize_t update_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
extern ssize_t update_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos);

#endif  /* _SECURITY_TRM_IO_H */