
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
#include <linux/random.h>

#include "../../includes/citadel.h"
#include "../../includes/task.h"
#include "../../includes/payload_io.h"

static void init_task_trm(citadel_task_data_t *data, citadel_task_data_t *previous)
{
    if (!previous) {
        data->in_realm = false;
        data->ticket_head = NULL;
        data->granted_pty = false;
        data->tagged = false;
        data->pid = 1;
    }
    else {
        data->in_realm = previous->in_realm;
        data->pid = (previous->pid == 0) ? 1 : previous->pid;
        data->granted_pty = previous->granted_pty;

        // TODO do we want this? Auto propagation of identifiers and tickets to children might be bad.
        data->ticket_head = previous->ticket_head;
        previous->ticket_head = NULL;
        data->tagged = previous->tagged;
        if (previous->tagged) memcpy(data->identifier, previous->identifier, _CITADEL_IDENTIFIER_LENGTH);

        mutex_destroy(&previous->lock);
    }
    
    get_random_bytes(data->identifier, sizeof(data->identifier));
    mutex_init(&data->lock);
}

/*
 *	@cred points to the credentials.
 *	@gfp indicates the atomicity of any memory allocations.
 *	Only allocate sufficient memory and attach to @cred such that
 *	cred_transfer() will not get ENOMEM.
 */
int trm_cred_alloc_blank(struct cred *cred, gfp_t gfp)
{
	init_task_trm(citadel_cred(cred), NULL);
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
    // if (system_ready()) {
    //     printk(PFX "cred_prepare called from PID %d\n", current->pid);
    // }
    init_task_trm(citadel_cred(new), citadel_cred(old));
    return 0;
}

// TODO cred_transfer

int trm_task_prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5) {
    task_housekeeping();
    return 0;
}

int trm_task_kill(struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    citadel_task_data_t *task_data = citadel_cred(cred);
    if (task_data && task_data->in_realm) {
        printk(PFX "Tainted process, PID %d, being killed (sig: %d)\n", p->pid, sig);
    }
    return 0;
}


void trm_task_free(struct task_struct *task) {
    // printk(PFX "PID %d freed.\n", task->pid);
    // Remove entries from the ticket cache.
}

void trm_cred_free(struct cred *cred) {
    citadel_task_data_t *task_data = citadel_cred(cred);
    if (task_data && task_data->ticket_head) printk(PFX "Need to free tickets for PID %d\n", task_data->pid);
    // Free tickets held by the task.
}


// int task_alloc(struct task_struct *task, unsigned long clone_flags) {

// }

// void trm_bprm_committed_creds(struct linux_binprm *bprm) {
//     citadel_task_data_t *task_data = citadel_cred(bprm->cred);

//     // PID 0: swapper & scheduler.
//     // PID 1: Init process.
//     // PID 2: kthread root process.
//     if (task_data && current->pid > 2) {
//         printk(PFX "Assigned PID\n")
//         task_data->pid = current->pid;
//     }
// }