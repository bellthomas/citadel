
#include "interface.h"

uint8_t asm_handle_request(struct citadel_op_request *request) {
    ocall_print("asm_handle_request");
    return CITADEL_OP_APPROVED;
}
