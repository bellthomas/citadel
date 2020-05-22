#ifndef _SECURITY_TRM_TASK_H
#define _SECURITY_TRM_TASK_H

extern int trm_cred_alloc_blank(struct cred *cred, gfp_t gfp);
extern int trm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp);
extern int trm_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);
extern int trm_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred);

#endif