

#ifndef __CITADEL_SHARED_DEFINITIONS_H
#define __CITADEL_SHARED_DEFINITIONS_H

// Generic.
#define _TRM_IDENTIFIER_LENGTH 16
#define _TRM_AES_KEY_LENGTH 16
#define _TRM_RSA_KEY_LENGTH 256
#define _TRM_SIGNATURE_LENGTH 8
#define _TRM_PID_LENGTH 4

#define _TRM_SECURITYFS_ROOT "/sys/kernel/security/citadel/"
#define _TRM_PROCESS_GET_PTOKEN_PATH _TRM_SECURITYFS_ROOT "get_ptoken"
#define _TRM_LSM_CHALLENGE_PATH _TRM_SECURITYFS_ROOT "challenge"
#define _TRM_LSM_UPDATE_PATH _TRM_SECURITYFS_ROOT "update"

// Parameters for GCM-AES-128.
#define IV_LENGTH 12
#define TAG_LENGTH 16

// Challenge.
#define _TRM_CHALLENGE_LENGTH 32
#define _TRM_NAME_LENGTH 40
#define _TRM_MAX_RSA_PAYLOAD 214
#define _TRM_CHALLENGE_PADDING (0 + _TRM_MAX_RSA_PAYLOAD - _TRM_PID_LENGTH - _TRM_NAME_LENGTH - _TRM_CHALLENGE_LENGTH - _TRM_AES_KEY_LENGTH - _TRM_SIGNATURE_LENGTH)

// Updates.
#define _TRM_UPDATE_SUBJECT_LENGTH _TRM_IDENTIFIER_LENGTH
#define _TRM_UPDATE_DATA_LENGTH 32
#define _TRM_XATTR_INSTALL_ID "security.citadel.install" // TODO unify

#define XATTR_ACCEPTED_SIGNAL 359
#define XATTR_REJECTED_SIGNAL 360


// Userspace.
#define _TRM_PROCESS_PTOKEN_LENGTH 8
#define _TRM_PROCESS_SIGNED_PTOKEN_LENGTH (0 + _TRM_PROCESS_PTOKEN_LENGTH + _TRM_PID_LENGTH + _TRM_SIGNATURE_LENGTH + IV_LENGTH + TAG_LENGTH)
#define _TRM_PTOKEN_PAYLOAD_SIZE (0 + _TRM_SIGNATURE_LENGTH + _TRM_PROCESS_PTOKEN_LENGTH + _TRM_PID_LENGTH + _TRM_PROCESS_SIGNED_PTOKEN_LENGTH)

#define CITADEL_IPC_FILE "/run/citadel.socket"
#define CITADEL_IPC_ADDRESS "ipc://" CITADEL_IPC_FILE
#define CITADEL_ENV_ATTR_NAME "CITADEL_PTOKEN"
#define CITADEL_SIGNED_ENV_ATTR_NAME "CITADEL_SIGNED_PTOKEN"


static const unsigned char challenge_signature[_TRM_SIGNATURE_LENGTH] = { 0x80, 0x70, 0x60, 0x50, 0x40, 0x30, 0x20, 0x10 };

// Needs to be 214 bytes.
struct trm_challenge {
    unsigned char signature[_TRM_SIGNATURE_LENGTH];
    unsigned char challenge[_TRM_CHALLENGE_LENGTH];
    unsigned char name[_TRM_NAME_LENGTH];
    unsigned char key[_TRM_AES_KEY_LENGTH];
    int32_t pid; /* pid_t */
    unsigned char padding[_TRM_CHALLENGE_PADDING];
};

struct trm_update_header {
    unsigned char signature[_TRM_SIGNATURE_LENGTH];
    unsigned char key_update[_TRM_AES_KEY_LENGTH];
    uint8_t records;
};

struct trm_update_record {
    unsigned char subject[_TRM_UPDATE_SUBJECT_LENGTH];
    unsigned char data[_TRM_UPDATE_DATA_LENGTH];
};

struct trm_ptoken {
    unsigned char signature[_TRM_SIGNATURE_LENGTH];
    int32_t citadel_pid; /* pid_t */
    unsigned char ptoken[_TRM_PROCESS_PTOKEN_LENGTH];
    unsigned char signed_ptoken[_TRM_PROCESS_SIGNED_PTOKEN_LENGTH]; // Encrypted trm_ptoken_protected.
};

struct trm_ptoken_protected {
    unsigned char signature[_TRM_SIGNATURE_LENGTH];
    int32_t pid; /* pid_t */
    unsigned char ptoken[_TRM_PROCESS_PTOKEN_LENGTH];
};

#endif /* __CITADEL_SHARED_DEFINITIONS_H */
