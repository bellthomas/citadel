
#include <linux/types.h>
#include <linux/xattr.h>
#include <linux/binfmts.h>
#include <linux/lsm_hooks.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/uidgid.h>
#include <linux/kobject.h>
#include <linux/crypto.h>
#include <linux/mutex.h>
#include <linux/dcache.h>

#include "../../includes/citadel.h"
#include "../../includes/task.h"
#include "../../includes/payload_io.h"

static void init_task_trm(citadel_task_data_t *tt, citadel_task_data_t *tt_old)
{
    if (!tt_old) {
        tt->ticket_head = NULL;
    }
    
	// tsp->smk_task = task;
	// tsp->smk_forked = forked;
	// INIT_LIST_HEAD(&tsp->smk_rules);
	// INIT_LIST_HEAD(&tsp->smk_relabel);
	// mutex_init(&tsp->smk_rules_lock);
}

/*
 *	@cred points to the credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Only allocate sufficient memory and attach to @cred such that
 *	cred_transfer() will not get ENOMEM.
 */
int trm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	init_task_trm(trm_cred(cred), NULL);
	return 0;
}

/*
 *	@new points to the new credentials.
 *	@old points to the original credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Prepare a new set of credentials by copying the data from the old set.
 */
int trm_cred_prepare(struct cred *new, const struct cred *old, gfp_t gfp)
{
    if (system_ready()) {
        // printk(PFX "cred_prepare called from PID %d\n", current->pid);
    }
    // init_task_trm(trm_cred(cred), trm_cred(old));
    return 0;
}

int trm_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    task_housekeeping();
    return 0;
}

int trm_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    citadel_task_data_t *task_data = trm_cred(cred);
    if (task_data && task_data->in_realm) {
        printk(PFX "Tainted process, PID %d, being killed (sig: %d)\n", p->pid, sig);
    }
    return 0;
}
