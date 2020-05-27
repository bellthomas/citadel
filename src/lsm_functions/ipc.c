
#include <linux/types.h>

#include "../../includes/citadel.h"
#include "../../includes/ipc.h"
#include "../../includes/payload_io.h"
#include "../../includes/shm_tracking.h"

/*
 *	Allocate and attach a security structure to the @perm->security
 *	field. The security field is initialized to NULL when the structure is
 *	first created.
 *	@perm contains the IPC permissions of the shared memory structure.
 *	Return 0 if operation was successful and permission is granted.
 */
int trm_ipc_alloc_security(struct kern_ipc_perm *isp) {
	citadel_ipc_data_t *ipc_data = citadel_ipc(isp);
    char *hex;
    ipc_data->in_realm = 0;
    memcpy(ipc_data->identifier, &isp->key, sizeof(key_t));
    memset(ipc_data->identifier + sizeof(key_t), 0, sizeof(ipc_data->identifier) - sizeof(key_t));

    hex = to_hexstring(ipc_data->identifier, sizeof(ipc_data->identifier));
    printk(PFX "SHM alloc: %s\n", hex);
    kfree(hex);

	return 0;
}


/*
 *	Deallocate the security structure @perm->security for the memory segment.
 *	@perm contains the IPC permissions of the shared memory structure.
 */
void trm_ipc_free_security(struct kern_ipc_perm *isp) {
    citadel_ipc_data_t *ipc_data = citadel_ipc(isp);
    ipc_data->in_realm = 1;
    memset(ipc_data->identifier, 0, sizeof(ipc_data->identifier));
}

static int allow_shm_access(key_t key) {
    printk(PFX "Allow SHM access (%d)\n", key);
    if (unlikely(!current) || unlikely(current->pid < 2)) return 0;
    // if (unlikely(!key)) return 0; // TODO check?
    return add_to_shmid(key, current->pid) ? 0 : -EIO;
}

static int shm_can_access(struct kern_ipc_perm *perm) {
    citadel_task_data_t *cred = citadel_cred(current_cred());
    citadel_ipc_data_t *ipc_data = citadel_ipc(perm);
    citadel_ticket_t *current_ticket;
    ktime_t tracker;
    bool found = false;
    size_t tmp;

    printk(PFX "Can SHM access (%d)\n", perm->key);

    // Invalid.
    if (unlikely(!ipc_data) || unlikely(!cred)) return allow_shm_access(perm->key);

    // If untainted, allow untainted processes to join.
    if (!cred->in_realm && !ipc_data->in_realm) return allow_shm_access(perm->key);

    // Citadel always allowed to access.
	if (unlikely(current->pid == citadel_pid())) return allow_shm_access(perm->key);

    // Let's see if the process has the correct ticket.
	current_ticket = cred->ticket_head;
	tracker = 0;
	while (current_ticket->timestamp > tracker && !found) {

		// Check if this ticket allows access.
		found = true;
		for (tmp = 0; tmp < _CITADEL_IDENTIFIER_LENGTH; tmp++) {
			if (current_ticket->detail.identifier[tmp] != ipc_data->identifier[tmp]) {
				found = false;
				break;
			}
		}

		// Check if this enables the requested operation.
		if (found && (current_ticket->detail.operation & CITADEL_OP_SHM) == 0)
			found = false;

		if (!found) {
			tracker = current_ticket->timestamp;
			current_ticket = current_ticket->next;
		}
	}

    if (found) {
		// Found a ticket relating to this object.
		printk(PFX "Allowing PID %d access to SHM %d\n", current->pid, perm->key);
		if (ipc_data->in_realm) cred->in_realm = true;
		if (cred->in_realm) ipc_data->in_realm = true;

		return allow_shm_access(perm->key);
    }
   
    printk(PFX "Rejecting PID %d access to SHM %d\n", current->pid, perm->key);
    return -EACCES;
}

/*
 *	Check permission when a shared memory region is requested through the
 *	shmget system call. This hook is only called when returning the shared
 *	memory region identifier for an existing region, not when a new shared
 *	memory region is created.
 *	@perm contains the IPC permissions of the shared memory structure.
 *	@shmflg contains the operation control flags.
 *	Return 0 if permission is granted.
 */
int trm_shm_associate(struct kern_ipc_perm *perm, int shmflg) {
    return shm_can_access(perm);
}


/*
 *	Check permission when a shared memory control operation specified by
 *	@cmd is to be performed on the shared memory region with permissions @perm.
 *	The @perm may be NULL, e.g. for IPC_INFO or SHM_INFO.
 *	@perm contains the IPC permissions of the shared memory structure.
 *	@cmd contains the operation to be performed.
 *	Return 0 if permission is granted.
 */
int trm_shm_shmctl(struct kern_ipc_perm *perm, int cmd) {
    return shm_can_access(perm);
}


/*
 *	Check permissions prior to allowing the shmat system call to attach the
 *	shared memory segment with permissions @perm to the data segment of the
 *	calling process. The attaching address is specified by @shmaddr.
 *	@perm contains the IPC permissions of the shared memory structure.
 *	@shmaddr contains the address to attach memory region to.
 *	@shmflg contains the operational flags.
 *	Return 0 if permission is granted.
 */
int trm_shm_shmat(struct kern_ipc_perm *perm, char __user *shmaddr, int shmflg) {
    return shm_can_access(perm);
}