
#ifndef _LIBCITADEL_CACHE_H
#define _LIBCITADEL_CACHE_H

#include <sys/time.h>

#include "_citadel_shared.h"

typedef struct libcitadel_cache_item {
    void *data;
    struct libcitadel_cache_item *next;
    struct timespec time;
    citadel_operation_t op;
} libcitadel_cache_item_t;


#define LIBCITADEL_CACHE_MAX_GROUPS 1

#define LIBCITADEL_CACHE_FILE_NAMES 0

extern libcitadel_cache_item_t *create_cache_entry(uint8_t group);
extern libcitadel_cache_item_t *cache_group_head(uint8_t group);
extern void init_cache(void);

#endif
