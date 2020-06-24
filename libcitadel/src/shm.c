
#include "../include/citadel/shm.h"


static bool shm_cache_hit(int key, bool is_shmid) {
	// Check cache.
	libcitadel_cache_item_t *head = cache_group_head(LIBCITADEL_CACHE_SHM);
	while (head) {
		if ((!is_shmid && key == head->fd) || (is_shmid && key == head->shmid)) {
			return true;
		}
		head = head->next;
	}
	return false;
}

bool citadel_shm_access(int key, bool is_shmid) {

	// Check the cache.
	if (shm_cache_hit(key, is_shmid)) {
		citadel_printf("(*) Enabled SHM access: %u (%s)\n", key, is_shmid ? "SHMID" : "Key");
		return true;
	}
	if (is_shmid) return false;

    struct citadel_op_request payload;
	memcpy(payload.signature, challenge_signature, sizeof(challenge_signature));
	payload.operation = CITADEL_OP_SHM;
	memcpy(payload.signed_ptoken, get_signed_ptoken(), sizeof(payload.signed_ptoken));
    memcpy(payload.subject, &key, sizeof(key_t));
    memset(payload.subject + sizeof(key_t), 0, sizeof(payload.subject) - sizeof(key_t));

	bool success = ipc_transaction((unsigned char*)&payload, sizeof(struct citadel_op_request));
	if (success) {
		citadel_printf("Enabled SHM access: %u\n", key);
		libcitadel_cache_item_t *entry = create_cache_entry(LIBCITADEL_CACHE_SHM);
		entry->op = 0;
		entry->fd = key;
		entry->data = NULL;
	} else {
		citadel_perror("Rejected SHM access: %u\n", key);
	}
	return success;
}

void declare_shmid_from_key(key_t key, int shmid) {
	citadel_printf("Associating SHM key %d with SHMID %d\n", key, shmid);
	libcitadel_cache_item_t *head = cache_group_head(LIBCITADEL_CACHE_SHM);
	while (head) {
		if (key == head->fd) {
			head->shmid = shmid;
			return;
		}
		head = head->next;
	}
}