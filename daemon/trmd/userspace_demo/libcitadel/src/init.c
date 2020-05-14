

#include "../include/citadel/init.h"

static char *generate_random_key(void) {
    char *key = (char*) malloc(CITADEL_ENV_KEY_SIZE + 1);
    for (size_t i = 0 ; i < CITADEL_ENV_KEY_SIZE; i++) key[i] = (rand()%(90-65))+65;
    key[CITADEL_ENV_KEY_SIZE] = '\0';
    return key;
}

int citadel_init(void) {
    char *key = generate_random_key();
    int set_env = setenv(CITADEL_ENV_ATTR_NAME, key, 1);
    printf("%s, %d\n", key, set_env);
    return 0;
}