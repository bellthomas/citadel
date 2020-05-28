
#include <sys/time.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

#include "../include/citadel/cache.h"
#include "../include/citadel/citadel.h"

static libcitadel_cache_item_t* cache_groups[LIBCITADEL_CACHE_MAX_GROUPS];

void init_cache(void) {
    for (int i = 0; i < LIBCITADEL_CACHE_MAX_GROUPS; i++)
        cache_groups[i] = NULL;
}

// static void free_cache_item(libcitadel_cache_item_t* item, uint8_t group) {
//     switch (group) {
//     case LIBCITADEL_CACHE_FILE_NAMES:

//     }
// }

void cleanup_cache_group(uint8_t group) {
    uint64_t delta_s;
    libcitadel_cache_item_t* current = cache_groups[group];
    libcitadel_cache_item_t* head = cache_groups[group];
    libcitadel_cache_item_t* prev;
    if (current == NULL) return;

    // Debug
    int count = 0;
    while (current) {
        count++;
        current = current->next;
    }
    citadel_cache("Cleaning. Currently got %d entries...\n", count);
    current = cache_groups[group];

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);

    // Clean up expired tickets.
    while(current) {
        delta_s = now.tv_sec - current->time.tv_sec;
        if (delta_s < _CITADEL_TICKET_EXPIRY) break;
        current = current->next;
    }

    // Current is either NULL or pointing to the first valid ticket.
    while (head != current) {
        prev = head;
        head = head->next;
        if (prev->data) free(prev->data);
        free(prev);
    }
    cache_groups[group] = current;
}

libcitadel_cache_item_t *cache_group_head(uint8_t group) {
    citadel_cache("Fetching cache head\n");
    if (group >= LIBCITADEL_CACHE_MAX_GROUPS) return NULL;
    if (group == LIBCITADEL_CACHE_FILE_NAMES) cleanup_cache_group(group);
    return cache_groups[group];
}

libcitadel_cache_item_t *create_cache_entry(uint8_t group) {
    citadel_cache("Creating cache entry\n");
    if (group >= LIBCITADEL_CACHE_MAX_GROUPS) return NULL;
    libcitadel_cache_item_t* item = (libcitadel_cache_item_t*)malloc(sizeof(libcitadel_cache_item_t));
    if (!item) return NULL;
    item->next = NULL;
    item->op = 0;
    clock_gettime(CLOCK_MONOTONIC_RAW, &item->time);

    if (cache_groups[group] == NULL) {
        cache_groups[group] = item;
    }
    else {
        libcitadel_cache_item_t* current = cache_groups[group];
        while(current->next) current = current->next;
        current->next = item;
    }
}

bool entry_in_date(libcitadel_cache_item_t *item) {
    if (!item) return false;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC_RAW, &now);
    uint64_t delta_s = now.tv_sec - item->time.tv_sec + 1;
    return (delta_s < _CITADEL_TICKET_EXPIRY);
}

libcitadel_cache_item_t *pop_group_head(uint8_t group) {
    if (group >= LIBCITADEL_CACHE_MAX_GROUPS) return NULL;
    if (!cache_groups[group]) return NULL;

    libcitadel_cache_item_t *old = cache_groups[group];
    cache_groups[group] = old->next;
    return old;
}

void update_cache_timestamp(libcitadel_cache_item_t *item) {
    clock_gettime(CLOCK_MONOTONIC_RAW, &item->time);
}

void move_cache_item_to_end(libcitadel_cache_item_t *item, libcitadel_cache_item_t *prev, uint8_t group) {
    if (!prev && !item->next) return;

    if (!prev) pop_group_head(group);
    else prev->next = item->next;

    libcitadel_cache_item_t *current = item;
    while(current->next) current = current->next;
    current->next = item;
    item->next = NULL;
}
/*




 fd -> (id, op)
 */