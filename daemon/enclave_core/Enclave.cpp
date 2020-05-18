
#include "includes/enclave.h"

// Hex printing facility.
static unsigned char hex_buffer[2*CITADEL_MAX_METADATA_SIZE+1] = {'\0'};

void load_hex_buffer(unsigned char *buf, unsigned int len) {
    size_t  i;
    if (buf == NULL || len == 0) return;
    for (i=0; i<len && i<CITADEL_MAX_METADATA_SIZE; i++) {
        hex_buffer[i*2]   = "0123456789ABCDEF"[buf[i] >> 4];
        hex_buffer[i*2+1] = "0123456789ABCDEF"[buf[i] & 0x0F];
    }
    hex_buffer[len*2] = '\0';
}

void reset_hex_buffer() {
    size_t i;
    for (i = 0; i < sizeof(hex_buffer); i++) 
        hex_buffer[i] = '\0';
}

void print_hex(unsigned char *buf, unsigned int len) {
    load_hex_buffer(buf, len);
    enclave_printf("%s", hex_buffer);
}

void timer_pulse(void) {
    for(int i=1; i<=5; i++) generate_ticket(i);
    enclave_printf("Timer");
    // Install xattr record.
    char path[22] = "/opt/testing_dir/test";
    generate_xattr_ticket(path);
}

//
int generate_random_number() {
    enclave_printf("Processing random number generation...");
    return 0;
}

