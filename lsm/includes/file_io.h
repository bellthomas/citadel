

#ifndef _SECURITY_TRM_IO_H
#define _SECURITY_TRM_IO_H


#define CHALLENGE_MAX_SIZE 256 // Using 2048-bit RSA.

// file_io.c
extern ssize_t challenge_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
extern ssize_t challenge_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos);
extern ssize_t sealed_keys_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
extern ssize_t update_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);
extern ssize_t update_receive(struct file *file, const char __user *buf, size_t count, loff_t *ppos);
extern ssize_t ptoken_read(struct file *file, char __user *buf, size_t count, loff_t *ppos);

#endif  /* _SECURITY_TRM_IO_H */