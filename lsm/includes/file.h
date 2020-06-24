#ifndef _SECURITY_TRM_LSM_FILE_H
#define _SECURITY_TRM_LSM_FILE_H

extern int trm_file_permission(struct file *file, int mask);
extern int trm_file_ioctl(struct file *file, unsigned int cmd, unsigned long arg);
extern int trm_file_open(struct file *file);

#endif  /* _SECURITY_TRM_LSM_FILE_H */