
#include "interface.h"

uint8_t asm_handle_request(struct citadel_op_request *request, void *metadata) {
    // ocall_print("asm_handle_request");
    // if (metadata) {
    //     ocall_print((const char*)metadata);
    // }
    return CITADEL_OP_APPROVED;
}
