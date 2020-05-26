

#ifndef __CITADEL_SHARED_DEFINITIONS_H
#define __CITADEL_SHARED_DEFINITIONS_H

#define CITADEL_DEBUG 1

// Generic.
#define _CITADEL_LSM_NAME "citadel"
#define _CITADEL_IDENTIFIER_LENGTH 16
#define _CITADEL_ENCODED_IDENTIFIER_LENGTH (2 * _CITADEL_IDENTIFIER_LENGTH + 1) 
#define _CITADEL_SIGNATURE_LENGTH 8
#define _CITADEL_PID_LENGTH 4
#define _CITADEL_TICKET_EXPIRY 15  // seconds
#define _CITADEL_CACHE_EXPIRY 15  // seconds


// Parameters for RSA 2048-bit and GCM-AES-128.
#define _CITADEL_AES_KEY_LENGTH 16
#define _CITADEL_IV_LENGTH 12
#define _CITADEL_TAG_LENGTH 16
#define _CITADEL_RSA_KEY_LENGTH 256
#define _CITADEL_MAX_RSA_PAYLOAD 214


// Challenge.
#define _CITADEL_CHALLENGE_LENGTH 32
#define _CITADEL_ASM_NAME_LENGTH 40
#define _CITADEL_CHALLENGE_PADDING (0 + _CITADEL_MAX_RSA_PAYLOAD - _CITADEL_PID_LENGTH - _CITADEL_ASM_NAME_LENGTH - _CITADEL_CHALLENGE_LENGTH - _CITADEL_AES_KEY_LENGTH - _CITADEL_SIGNATURE_LENGTH)

// Updates.
// #define _TRM_UPDATE_SUBJECT_LENGTH _CITADEL_IDENTIFIER_LENGTH
// #define _TRM_UPDATE_DATA_LENGTH 32

// SecurityFS
#define _CITADEL_SECURITYFS_NS _CITADEL_LSM_NAME
#define _CITADEL_SECURITYFS_PTOKEN "get_ptoken"
#define _CITADEL_SECURITYFS_UPDATE "update"
#define _CITADEL_SECURITYFS_CHALLENGE "challenge"

#define _CITADEL_SECURITYFS_ROOT "/sys/kernel/security/" _CITADEL_SECURITYFS_NS "/"
#define _CITADEL_PROCESS_GET_PTOKEN_PATH _CITADEL_SECURITYFS_ROOT _CITADEL_SECURITYFS_PTOKEN
#define _CITADEL_LSM_CHALLENGE_PATH _CITADEL_SECURITYFS_ROOT _CITADEL_SECURITYFS_CHALLENGE
#define _CITADEL_LSM_UPDATE_PATH _CITADEL_SECURITYFS_ROOT _CITADEL_SECURITYFS_UPDATE

// XATTR.
#define _CITADEL_SECURITY_ROOT "security"
#define _CITADEL_XATTR_NAMESPACE _CITADEL_LSM_NAME
#define _CITADEL_XATTR_TAG_IN_REALM "in_realm"
#define _CITADEL_XATTR_TAG_IDENTIFIER "identifier"
#define _CITADEL_XATTR_TAG_INSTALL "install"

#define _CITADEL_XATTR_ROOT _CITADEL_SECURITY_ROOT "." _CITADEL_XATTR_NAMESPACE
#define _CITADEL_XATTR_IN_REALM _CITADEL_XATTR_ROOT "." _CITADEL_XATTR_TAG_IN_REALM
#define _CITADEL_XATTR_IDENTIFIER _CITADEL_XATTR_ROOT "." _CITADEL_XATTR_TAG_IDENTIFIER
#define _CITADEL_XATTR_INSTALL _CITADEL_XATTR_ROOT "." _CITADEL_XATTR_TAG_INSTALL

#define _CITADEL_XATTR_NS_TAG_IN_REALM _CITADEL_XATTR_NAMESPACE "." _CITADEL_XATTR_TAG_IN_REALM
#define _CITADEL_XATTR_NS_TAG_IDENTIFIER _CITADEL_XATTR_NAMESPACE "." _CITADEL_XATTR_TAG_IDENTIFIER

#define _CITADEL_XATTR_ACCEPTED_SIGNAL 359
#define _CITADEL_XATTR_REJECTED_SIGNAL 360


// Userspace.
#define _CITADEL_PROCESS_PTOKEN_LENGTH 8
#define _CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH (0 + _CITADEL_PROCESS_PTOKEN_LENGTH + _CITADEL_PID_LENGTH + _CITADEL_IDENTIFIER_LENGTH + _CITADEL_SIGNATURE_LENGTH + _CITADEL_IV_LENGTH + _CITADEL_TAG_LENGTH)
#define _CITADEL_PTOKEN_PAYLOAD_SIZE (0 + _CITADEL_SIGNATURE_LENGTH + _CITADEL_PROCESS_PTOKEN_LENGTH + _CITADEL_PID_LENGTH + _CITADEL_IDENTIFIER_LENGTH + _CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH)
#define _CITADEL_PTOKEN_LENGTH_DIFFERENCE 55  // citadel_op_request - citadel_op_reply (without padding)

#define _CITADEL_IPC_FILE "/run/" _CITADEL_LSM_NAME ".socket"
#define _CITADEL_IPC_ADDRESS "ipc://" _CITADEL_IPC_FILE
#define _CITADEL_ENV_ATTR_NAME "CITADEL_PTOKEN"
#define _CITADEL_SIGNED_ENV_ATTR_NAME "CITADEL_SIGNED_PTOKEN"
#define _CITADEL_MAX_METADATA_SIZE 4096  // Maximum Linux path length.

typedef uint8_t citadel_operation_t;
typedef uint8_t citadel_response_t;


static const unsigned char challenge_signature[_CITADEL_SIGNATURE_LENGTH] = { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };

// Needs to be 214 bytes.
typedef struct citadel_challenge {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    unsigned char challenge[_CITADEL_CHALLENGE_LENGTH];
    unsigned char name[_CITADEL_ASM_NAME_LENGTH];
    unsigned char key[_CITADEL_AES_KEY_LENGTH];
    int32_t pid; /* pid_t */
    unsigned char padding[_CITADEL_CHALLENGE_PADDING];
} citadel_challenge_t;

typedef struct citadel_update_header {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    unsigned char key_update[_CITADEL_AES_KEY_LENGTH];
    uint8_t records;
} citadel_update_header_t;

typedef struct citadel_update_record {
    int32_t pid;
    unsigned char identifier[_CITADEL_IDENTIFIER_LENGTH];
    citadel_operation_t operation;
} citadel_update_record_t;


typedef struct citadel_ptoken {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    int32_t citadel_pid; /* pid_t */
    unsigned char ptoken[_CITADEL_PROCESS_PTOKEN_LENGTH];
    unsigned char process_identifier[_CITADEL_IDENTIFIER_LENGTH];
    unsigned char signed_ptoken[_CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH]; // Encrypted citadel_ptoken_protected_t.
} citadel_ptoken_t;

typedef struct citadel_ptoken_protected {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    int32_t pid; /* pid_t */
    unsigned char ptoken[_CITADEL_PROCESS_PTOKEN_LENGTH];
    unsigned char process_identifier[_CITADEL_IDENTIFIER_LENGTH];
} citadel_ptoken_protected_t;


// Citadel operation (citadel_operation_t).
#define CITADEL_OP_NOP              0x00
#define CITADEL_OP_PTY_ACCESS       0x01  // Special, will persist indefinitely.
#define CITADEL_OP_REGISTER         0x02
#define CITADEL_OP_FILE_CREATE      0x04
#define CITADEL_OP_FILE_RECREATE    0x08
#define CITADEL_OP_FILE_OPEN        0x10
#define CITADEL_OP_SOCKET_INTERNAL  0x20
#define CITADEL_OP_SOCKET_EXTERNAL  0x40
#define CITADEL_OP_SOCKET           0x60  // CITADEL_OP_SOCKET_INTERNAL & CITADEL_OP_SOCKET_EXTERNAL

// Citadel request response (citadel_response_t).
// enum citadel_status {
//     CITADEL_OP_INVALID,
//     CITADEL_OP_FORGED,
//     CITADEL_OP_APPROVED,
//     CITADEL_OP_REJECTED,
//     CITADEL_OP_ERROR
// } citadel_status_t;

#define CITADEL_OP_INVALID   0
#define CITADEL_OP_FORGED    1
#define CITADEL_OP_APPROVED  2
#define CITADEL_OP_REJECTED  3
#define CITADEL_OP_GRANTED   4
#define CITADEL_OP_ERROR     5

static const char* citadel_status_names[] = {
    "Invalid operation",
    "Forgery detected",
    "Approved",
    "Rejected",
    "Ownership granted."
    "An internal error occurred",
};

static inline const char* citadel_error(uint8_t err_num) {
    if(err_num >= sizeof(citadel_status_names)) return "Invalid error";
    else return citadel_status_names[err_num];
}

struct citadel_op_request {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    citadel_operation_t operation;
    unsigned char subject[_CITADEL_IDENTIFIER_LENGTH];
    unsigned char signed_ptoken[_CITADEL_PROCESS_SIGNED_PTOKEN_LENGTH]; // Encrypted citadel_ptoken_protected_t.
};

struct citadel_op_reply {
    unsigned char signature[_CITADEL_SIGNATURE_LENGTH];
    citadel_operation_t operation;
    unsigned char subject[_CITADEL_IDENTIFIER_LENGTH];
    unsigned char ptoken[_CITADEL_PROCESS_PTOKEN_LENGTH];
    citadel_response_t result;
    uint8_t padding[_CITADEL_PTOKEN_LENGTH_DIFFERENCE];
};

struct citadel_op_extended_request {
    struct citadel_op_request request;
    bool translate;
    unsigned char metadata[_CITADEL_MAX_METADATA_SIZE];
};

struct citadel_op_extended_reply {
    struct citadel_op_reply reply;
    bool unused;
    unsigned char metadata[_CITADEL_MAX_METADATA_SIZE];
};


#endif /* __CITADEL_SHARED_DEFINITIONS_H */
