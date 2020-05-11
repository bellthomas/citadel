#ifndef _SECURITY_TRM_LSM_FILE_H
#define _SECURITY_TRM_LSM_FILE_H

#include "trm.h"

extern int trm_file_permission(struct file *file, int mask);

#endif  /* _SECURITY_TRM_LSM_FILE_H */