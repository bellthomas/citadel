
#include <sys/time.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <sys/xattr.h>

#include "../include/citadel/cache.h"
#include "../include/citadel/citadel.h"

static libcitadel_cache_item_t* cache_groups[LIBCITADEL_CACHE_MAX_GROUPS];

void init_cache(void) {
    for (int i = 0; i < LIBCITADEL_CACHE_MAX_GROUPS; i++)
        cache_groups[i] = NULL;
}

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
    citadel_cache("(%d) Cleaning. Currently got %d entries for (%d)...\n", getpid(), count, group);
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
    // citadel_cache("(%d) Fetching cache head\n", getpid());
    if (group >= LIBCITADEL_CACHE_MAX_GROUPS) return NULL;
    if (group == LIBCITADEL_CACHE_FILE_NAMES) cleanup_cache_group(group);
    return cache_groups[group];
}

libcitadel_cache_item_t *create_cache_entry(uint8_t group) {
    citadel_cache("(%d) Creating cache entry (%d)\n", getpid(), group);
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
    return item;
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

char *get_fd_identifier(int fd, bool *tainted) {
	char *id, *id_raw;

	if (tainted) *tainted = true;
	id = malloc(_CITADEL_ENCODED_IDENTIFIER_LENGTH);
    id[_CITADEL_ENCODED_IDENTIFIER_LENGTH-1] = '\0';
	ssize_t read = fgetxattr(fd, _CITADEL_XATTR_IDENTIFIER, id, _CITADEL_ENCODED_IDENTIFIER_LENGTH);
	
	if (read == _CITADEL_ENCODED_IDENTIFIER_LENGTH || read == _CITADEL_ENCODED_IDENTIFIER_LENGTH - 1) {
		// citadel_printf("(%d) File identifier: %s\n", getpid(), (char*)id);
	} else if (read == -1) {
		// citadel_printf("File not tainted.\n");
		if (tainted) *tainted = false;
		free(id);
		return NULL;
	}
	else {
		citadel_printf("(%d) Fail. Got %ld bytes for identifier\n", getpid(), read);
		free(id);
		return NULL;
	}

	id_raw = (char*)_hex_identifier_to_bytes(id);
	free(id);
	return id_raw;
}

bool citadel_validate_fd (int fd, char *identifier, citadel_operation_t *op,
    bool *tainted, citadel_update_function_t execute)
{
	bool ret = false;

	// If not supplied with the identifier get it.
	bool _taint = true;
	if (!identifier)
		identifier = get_fd_identifier(fd, &_taint);
	if (tainted) *tainted = _taint;
	if (!_taint) return true;


	// Check cache.
	libcitadel_cache_item_t *head = cache_group_head(LIBCITADEL_CACHE_FD);
	libcitadel_cache_item_t *prev = NULL, *tmp = NULL;
	while (head) {
		if (head->fd == fd) {
			if (!op || *op == head->op) {
				if (memcmp(identifier, head->data, _CITADEL_IDENTIFIER_LENGTH) == 0) {
					// This is the correct item.
					ret = true;
					if (entry_in_date(head)) goto bail_validate_fd;
                    else if (head->op & CITADEL_OP_NOP) goto bail_validate_fd;
                    citadel_cache("FD out of date.\n");

					// Out of date, refresh.
					ret = (*head->update)(fd, identifier, head->op, false);
					if (!ret) goto bail_validate_fd;

					update_cache_timestamp(head);
					if (head->next) move_cache_item_to_end(head, prev, LIBCITADEL_CACHE_FD);

					goto bail_validate_fd;
				}
			}
		}
		prev = head;
		head = head->next;
	}
	citadel_printf("(%d) FD not found in cache\n", getpid());

	if (op && execute) 
        ret = execute(fd, identifier, *op, true);

bail_validate_fd:
	if (identifier) free(identifier);
	return ret;
}

bool citadel_validate_fd_anon(int fd) {
    return citadel_validate_fd(fd, NULL, NULL, NULL, NULL);
}

static void prepare_entry_for_child(libcitadel_cache_item_t *item) {
    item->time = (struct timespec) { 0 };
    if (item->op == CITADEL_OP_NOP)
        item->op = CITADEL_OP_PARENT;
}

void cache_on_fork(void) {
    libcitadel_cache_item_t *head;
    for (int i = 0; i < LIBCITADEL_CACHE_MAX_GROUPS; i++) {
        if (cache_groups[i]) {
            head = cache_groups[i];
            prepare_entry_for_child(head);
            while (head->next) {
                prepare_entry_for_child(head->next);
                head = head->next;
            }
        }
    }
}

bool citadel_fd_is_declared(int fd) {
    if (fd == -1) return false;
    libcitadel_cache_item_t *head = cache_groups[LIBCITADEL_CACHE_FD];
    while(head) {
        if (head->fd == fd) return true;
        head = head->next;
    }
    return false;
}

void citadel_remove_fd(int fd) {
    libcitadel_cache_item_t *head = cache_groups[LIBCITADEL_CACHE_FD];
    if (head == NULL || fd == -1) return;

    libcitadel_cache_item_t *prev = head;
    head = prev->next;
    while (head) {
        if (head->fd == fd) {
            // Remove
            prev->next = head->next;
            if (head->data) free(head->data);
            free(head);
        }
        prev = head;
        head = prev->next;
    }


    // Check first.
    head = cache_groups[LIBCITADEL_CACHE_FD];
    if (head->fd == fd) {
        // remove head.
        cache_groups[LIBCITADEL_CACHE_FD] = head->next;
        if (head->data) free(head->data);
        free(head);
    }
}