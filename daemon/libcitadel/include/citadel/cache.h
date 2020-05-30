
#ifndef _LIBCITADEL_CACHE_H
#define _LIBCITADEL_CACHE_H

#include <sys/time.h>
#include <stdbool.h>
#include <stdint.h>

#include "_citadel_shared.h"

typedef struct libcitadel_cache_item {
    void *data;
    struct libcitadel_cache_item *next;
    struct timespec time;
    citadel_operation_t op;
    int fd;
    int shmid;
    bool (*update)(int, char*, citadel_operation_t, bool);
} libcitadel_cache_item_t;

typedef bool (*citadel_update_function_t)(int, char*, citadel_operation_t, bool);

#define LIBCITADEL_CACHE_MAX_GROUPS 3

#define LIBCITADEL_CACHE_FILE_NAMES 0
#define LIBCITADEL_CACHE_FD 1
#define LIBCITADEL_CACHE_SHM 2

extern libcitadel_cache_item_t *create_cache_entry(uint8_t group);
extern libcitadel_cache_item_t *cache_group_head(uint8_t group);
extern void init_cache(void);
extern bool entry_in_date(libcitadel_cache_item_t *item);
extern libcitadel_cache_item_t *pop_group_head(uint8_t group);
extern void update_cache_timestamp(libcitadel_cache_item_t *item);
extern void move_cache_item_to_end(libcitadel_cache_item_t *item, libcitadel_cache_item_t *prev, uint8_t group);
extern bool citadel_validate_fd(int fd, char *identifier, citadel_operation_t *op, bool *tainted, citadel_update_function_t execute);
extern char *get_fd_identifier(int fd, bool *tainted);
extern bool citadel_validate_fd_anon(int fd);
#endif
