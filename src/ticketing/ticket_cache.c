
#include "../../includes/ticket_cache.h"

struct rb_root ticketing_reservations = RB_ROOT;
// struct rb_root_cached ticketing_reservations = RB_ROOT_CACHED;


struct ticket_reservation_node *ticket_search(struct rb_root *root, pid_t pid)
{
  	struct rb_node *node = root->rb_node;

  	while (node) {
  		struct ticket_reservation_node *data = container_of(node, struct ticket_reservation_node, node);
		int result;

		result = (pid - data->pid);

		if (result < 0)
  			node = node->rb_left;
		else if (result > 0)
  			node = node->rb_right;
		else
  			return data;
	}
	return NULL;
}

bool ticket_insert(struct rb_root *root, struct ticket_reservation_node *data)
{
  	struct rb_node **new = &(root->rb_node), *parent = NULL;

  	/* Figure out where to put new node */
  	while (*new) {
  		struct ticket_reservation_node *this = container_of(*new, struct ticket_reservation_node, node);
  		int result = (data->pid - this->pid);

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



void check_ticket_cache() {
    // int res;
    int count = 1;
    ktime_t expiry_threshold, last_to_free;
    citadel_ticket_t *current_ticket, *initial_ticket;
    citadel_task_data_t *task_data = trm_cred(current_cred());
    struct ticket_reservation_node *reservation_node = ticket_search(&ticketing_reservations, current->pid);
    if (reservation_node && reservation_node->ticket_head) {
        task_data->t_data = 4;

        current_ticket = reservation_node->ticket_head;
        while (current_ticket->timestamp < current_ticket->next->timestamp) {
            current_ticket = current_ticket->next;
            count++;
        }

        if (current->pid > 1) printk(PFX "PID %d has %d tickets in the cache to install.\n", current->pid, count);

        // Append to the task's ticket list.
        if (task_data->ticket_head == NULL) {
            // No tickets attached yet.
            task_data->ticket_head = current_ticket;
        }
        else {
            current_ticket = reservation_node->ticket_head->pre;
            reservation_node->ticket_head->prev = task_data->ticket_head->prev;
            current_ticket->next = task_data->ticket_head;
        }

        reservation_node->ticket_head = NULL;
    }

    // Remove old tickets.
    if (task_data->ticket_head) {
        expiry_threshold = ktime_get() + 15 * 1000 * 1000 * 1000; // 15 seconds.
        initial_ticket = task_data->ticket_head;
        current_ticket = task_data->ticket_head;
        while(current_ticket->timestamp <= expiry_threshold && current_ticket->timestamp < current_ticket->next->timestamp) {
            last_to_free = current_ticket->timestamp;
            current_ticket = current_ticket->next;
        }

        if (current_ticket->timestamp <= expiry_threshold) {
            last_to_free = current_ticket->timestamp;
            task_data->ticket_head = NULL;
        }
        else {
            current_ticket->prev = task_data->ticket_head->prev;
            task_data->ticket_head->prev->next = current_ticket;
            task_data->ticket_head = current_ticket;
        }
        
        // Free discarded tickets.
        while (initial_ticket->timestamp <= last_to_free) {
            current_ticket = initial_ticket;
            initial_ticket = initial_ticket->next;
            kfree(current_ticket);
        }
    }
}

bool insert_ticket(citadel_update_record_t *record) {
    int res;
    citadel_ticket_t *current_ticket, *tmp;
    citadel_ticket_t *ticket = kzalloc(sizeof(citadel_ticket_t), GFP_KERNEL);
    struct ticket_reservation_node *reservation_node = ticket_search(&ticketing_reservations, record->pid);
    if (!reservation_node) {
        reservation_node = kzalloc(sizeof(struct ticket_reservation_node), GFP_KERNEL);
        if (!reservation_node) {
            if (ticket) kfree(ticket);
            return false;
        }
        reservation_node->pid = record->pid;
        reservation_node->ticket_head = NULL;
        res = ticket_insert(&ticketing_reservations, reservation_node);
        if(res) {
            kfree(reservation_node);
            return false;
        }
    } 

    // Assert: reservation_node valid and in tree.
    ticket = kzalloc(sizeof(citadel_ticket_t), GFP_KERNEL);
    if (!ticket) return false;

    // Set ticket details.
    // TODO finish
    ticket->timestamp = ktime_get();
    ticket->detail.val = 2;

    current_ticket = reservation_node->ticket_head;
    if (!current_ticket) {
        // This is the first ticket.
        reservation_node->ticket_head = ticket;
        ticket->next = ticket;
        ticket->prev = ticket;
    } else {
        // Set head's prev to the new ticket and move to the terminal node.
        tmp = current_ticket->prev;
        current_ticket->prev = ticket;
        current_ticket = tmp;

        // Wire new ticket into the end of the list.
        ticket->next = current_ticket->next;
        ticket->prev = current_ticket;
        current_ticket->next = ticket;
    }


// else {
//         reservation_node = kzalloc(sizeof(struct ticket_reservation_node), GFP_KERNEL);
//         reservation_node->pid = pid;
//         res = ticket_insert(&ticketing_reservations, reservation_node);
//         if (pid > 500) printk(PFX "Installing PID %d, success %d\n", pid, res);
//     }

    // struct mytype *data = mysearch(&mytree, "walrus");

    // if (data) {
    //  rb_erase(&data->node, &mytree);
    //  // rb_erase_cached
    //  myfree(data);
    // }
    return true;
}