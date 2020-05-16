

#ifndef _LIBCITADEL_INTERFACE_H
#define _LIBCITADEL_INTERFACE_H

#define CITADEL_ENV_KEY_SIZE 16

struct citadel_ipc_message {
    char key[CITADEL_ENV_KEY_SIZE];
};

#endif