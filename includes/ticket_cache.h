
#ifndef _SECURITY_TRM_CACHE_H
#define _SECURITY_TRM_CACHE_H

#include <linux/rbtree.h>

#include "citadel.h"

struct ticket_reservation_node {
  	struct rb_node node;
    pid_t pid;
    citadel_ticket_t *ticket_head;
};

extern void check_ticket_cache(void);
extern bool insert_ticket(citadel_update_record_t *record);

#endif  /* _SECURITY_TRM_CACHE_H */