#ifndef _SECURITY_TRM_IPC_H
#define _SECURITY_TRM_IPC_H

#include <linux/types.h>

extern int trm_ipc_alloc_security(struct kern_ipc_perm *isp);
extern void trm_ipc_free_security(struct kern_ipc_perm *perm);
extern int trm_shm_associate(struct kern_ipc_perm *perm, int shmflg);
extern int trm_shm_shmctl(struct kern_ipc_perm *perm, int cmd);
extern int trm_shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr, int shmflg);

#endif