
#ifndef _SECURITY_TRM_CACHE_H
#define _SECURITY_TRM_CACHE_H

#include <linux/rbtree.h>

#include "citadel.h"

struct ticket_reservation_node {
  	struct rb_node node;
    pid_t pid;
    citadel_ticket_t *ticket_head;
};

typedef struct citadel_ticket_detail {
    int val;
} citadel_ticket_detail_t;

typedef struct citadel_ticket {
    citadel_ticket_detail_t detail;
    struct citadel_ticket *next, *prev;
} citadel_ticket_t;

extern void check_ticket_cache(void);

#endif  /* _SECURITY_TRM_CACHE_H */