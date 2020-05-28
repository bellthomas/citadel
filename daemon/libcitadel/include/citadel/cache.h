
#ifndef _LIBCITADEL_CACHE_H
#define _LIBCITADEL_CACHE_H

#include <sys/time.h>

#include "_citadel_shared.h"

typedef struct libcitadel_cache_item {
    void *data;
    struct libcitadel_cache_item *next;
    struct timespec time;
    citadel_operation_t op;
    int fd;
} libcitadel_cache_item_t;


#define LIBCITADEL_CACHE_MAX_GROUPS 2

#define LIBCITADEL_CACHE_FILE_NAMES 0
#define LIBCITADEL_CACHE_SOCKET_FD 1

extern libcitadel_cache_item_t *create_cache_entry(uint8_t group);
extern libcitadel_cache_item_t *cache_group_head(uint8_t group);
extern void init_cache(void);
extern bool entry_in_date(libcitadel_cache_item_t *item);
extern libcitadel_cache_item_t *pop_group_head(uint8_t group);
extern void update_cache_timestamp(libcitadel_cache_item_t *item);
extern void move_cache_item_to_end(libcitadel_cache_item_t *item, libcitadel_cache_item_t *prev, uint8_t group);

#endif
