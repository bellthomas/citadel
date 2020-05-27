
#ifndef _SECURITY_TRM_SHM_TRACKING_H
#define _SECURITY_TRM_SHM_TRACKING_H

typedef struct shm_id_pid {
    pid_t pid;
    struct shm_id_pid *next; 
} citadel_shm_pid_t;

typedef struct shm_id_node {
    struct rb_node node;
    key_t shmid;
    citadel_shm_pid_t *pid_head;
} citadel_shm_node_t;

extern size_t get_shmid_inhabitants(char* keystring, bool alloc, void **buffer);

#endif