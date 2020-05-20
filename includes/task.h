#ifndef _SECURITY_TRM_TASK_H
#define _SECURITY_TRM_TASK_H

#include "citadel.h"

extern int trm_cred_alloc_blank(struct cred *cred, gfp_t gfp);
extern int trm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);

#endif