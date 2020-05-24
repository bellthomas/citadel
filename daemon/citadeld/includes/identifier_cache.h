
#ifndef _U_ENCLAVE_TRM_ID_CACHE_H
#define _U_ENCLAVE_TRM_ID_CACHE_H

#include <algorithm>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <sparsehash/sparse_hash_map>

#include "app.h"

extern void identifier_cache_setup(void);
extern bool cache_passthrough(void *message, size_t message_len);

#endif