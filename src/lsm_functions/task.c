
#include "../../includes/task.h"

static void init_task_trm(struct task_trm *tt, struct task_trm *tt_old)
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
        printk(PFX "cred_prepare called from PID %d\n", current->pid);
    }
    // init_task_trm(trm_cred(cred), trm_cred(old));
    return 0;
}