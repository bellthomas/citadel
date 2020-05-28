

#ifndef _LIBCITADEL_FILE_H
#define _LIBCITADEL_FILE_H

#include "citadel.h"

extern bool citadel_file_claim(const char *path, size_t length);
extern bool citadel_file_claim_force(const char *path, size_t length);
extern bool citadel_file_open(const char *path, size_t length);

#endif