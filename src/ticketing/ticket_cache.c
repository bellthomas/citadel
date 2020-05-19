
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
    int res;
    struct ticket_reservation_node *reservation_node = ticket_search(&ticketing_reservations, task->pid);
    if (reservation_node) {
        // if (pid > 300) printk(PFX "PID %d is in the cache\n", pid);
    } 
}

bool insert_ticket(void) {
    int res;
    citadel_ticket_t *current, *tmp;
    citadel_ticket_t *ticket = kzalloc(sizeof(citadel_ticket_t), GFP_KERNEL);
    struct ticket_reservation_node *reservation_node = ticket_search(&ticketing_reservations, task->pid);
    if (!reservation_node) {
        reservation_node = kzalloc(sizeof(struct ticket_reservation_node), GFP_KERNEL);
        if (!reservation_node) {
            if (ticket) kfree(ticket);
            return false;
        }
        reservation_node->pid = pid;
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
    ticket->detail.val = 2;

    current = reservation_node->ticket_head;
    if (!current) {
        // This is the first ticket.
        reservation_node->ticket_head = ticket;
        ticket->next = ticket;
        ticket->prev = ticket;
    } else {
        // Set head's prev to the new ticket and move to the terminal node.
        tmp = current->prev;
        current->prev = ticket;
        current = tmp;

        // Wire new ticket into the end of the list.
        ticket->next = current->next;
        ticket->prev = current;
        current->next = ticket;
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
}