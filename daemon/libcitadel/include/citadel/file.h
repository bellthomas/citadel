

#ifndef _LIBCITADEL_FILE_H
#define _LIBCITADEL_FILE_H

#include "citadel.h"

extern bool citadel_file_create(char *path, size_t length);
extern bool citadel_file_recreate(char *path, size_t length);
extern bool citadel_file_open(char *path, size_t length);

#endif