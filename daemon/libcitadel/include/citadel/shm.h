
#ifndef _LIBCITADEL_SHM_H
#define _LIBCITADEL_SHM_H

#include <sys/types.h>

#include "citadel.h"

extern bool citadel_shm_access(int key, bool is_shmid);
extern void declare_shmid_from_key(key_t key, int shmid);

#endif