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
#include <linux/rbtree.h>

#include "../../includes/citadel.h"
#include "../../includes/shm_tracking.h"

struct rb_root shm_pool = RB_ROOT;

static citadel_shm_node_t *shmid_search(struct rb_root *root, key_t key)
{
  	struct rb_node *node = root->rb_node;

  	while (node) {
  		citadel_shm_node_t *data = container_of(node, citadel_shm_node_t, node);
		int result;

		result = (key - data->shmid);

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	}
	return NULL;
}

static bool insert_shmid(struct rb_root *root, citadel_shm_node_t *data)
{
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	/* Figure out where to put new node */
  	while (*new) {
  		citadel_shm_node_t *this = container_of(*new, citadel_shm_node_t, node);
  		int result = (data->shmid - this->shmid);

		parent = *new;
  		if (result < 0)
  			new = &((*new)->rb_left);
  		else if (result > 0)
  			new = &((*new)->rb_right);
  		else
  			return -1;
  	}

  	/* Add new node and rebalance tree. */
  	rb_link_node(&data->node, parent, new);
  	rb_insert_color(&data->node, root);
    // rb_insert_color_cached(&data->node, root);

	return 0;
}



bool add_to_shmid(key_t key, pid_t pid) {
    int res;
    citadel_shm_pid_t *shm_pid, *eol;
    citadel_shm_node_t *shm_node = shmid_search(&shm_pool, key);
    if (!shm_node) {
        shm_node = kzalloc(sizeof(citadel_shm_node_t), GFP_KERNEL);
        if (!shm_node) return false;
        shm_node->shmid = key;
        shm_node->pid_head = NULL;
        res = insert_shmid(&shm_pool, shm_node);
        if(res) {
            kfree(shm_node);
            return false;
        }
    }

    // First check we're not already there.
    shm_pid = shm_node->pid_head;
    while (shm_pid) {
        if (shm_pid->pid == pid) return true;
        eol = shm_pid;
        shm_pid = shm_pid->next;
    }

    // Create new entry.
    shm_pid = kzalloc(sizeof(citadel_shm_pid_t), GFP_KERNEL);
    if (!shm_pid) return false;
    shm_pid->pid = pid;
    shm_pid->next = NULL;

    // Add to end of existing list.
    eol->next = shm_pid;

    return true;
}

size_t get_shmid_inhabitants(char* keystring, bool alloc, void **buffer) {
    pid_t *pids;
    int count = 0;
    citadel_shm_pid_t *shm_pid;
    citadel_shm_node_t *shm_node;
    key_t *key;
    size_t res = 0;

    // Convert key to key_t.
    if (unlikely(strlen(keystring) != 2 * sizeof(key_t))) return -EINVAL;
    key = (key_t*)hexstring_to_bytes(keystring);
    printk(PFX "Getting for SHMID %s (%u)\n", keystring, *key);

    shm_node = shmid_search(&shm_pool, *key);
    kfree(key);
    if (!shm_node) return 0;

    // Traverse to find how much space we need.
    shm_pid = shm_node->pid_head;
    while (shm_pid) {
        count++;
        shm_pid = shm_pid->next;
    }
    
    // If the process hasn't requested the data, return.
    if (!alloc) return 2 * count * sizeof(pid_t) + 1;

    // Allocate space for PIDs.
    pids = kzalloc(count * sizeof(pid_t), GFP_KERNEL);
    if (!pids) return -ENOMEM;

    // Write PIDs to buffer.
    shm_pid = shm_node->pid_head;
    count = 0;
    while (shm_pid) {
        pids[count] = shm_pid->pid;
        count++;
    }

    // Encode and return.
    *buffer = to_hexstring((unsigned char*)pids, count * sizeof(pid_t));
    if (*buffer == NULL) res = -ENOMEM;
    else res = 2 * count * sizeof(pid_t) + 1;

    // TODO AES encrypt.
    // TODO Add current bit.

    if (pids) kfree(pids);
    return res;
}