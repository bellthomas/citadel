

#ifndef TRM_SHARED_DEFINITIONS_H_
#define TRM_SHARED_DEFINITIONS_H_

// Generic.
#define _TRM_IDENTIFIER_LENGTH 16
#define _TRM_AES_KEY_LENGTH 16
#define _TRM_RSA_KEY_LENGTH 256
#define _TRM_SIGNATURE_LENGTH 8
#define _TRM_PID_LENGTH 4

// Challenge.
#define _TRM_CHALLENGE_LENGTH 32
#define _TRM_NAME_LENGTH 40
#define _TRM_MAX_RSA_PAYLOAD 214
#define _TRM_CHALLENGE_PADDING (0 + _TRM_MAX_RSA_PAYLOAD - _TRM_PID_LENGTH - _TRM_NAME_LENGTH - _TRM_CHALLENGE_LENGTH - _TRM_AES_KEY_LENGTH - _TRM_SIGNATURE_LENGTH)

// Updates.
#define _TRM_UPDATE_SUBJECT_LENGTH _TRM_IDENTIFIER_LENGTH
#define _TRM_UPDATE_DATA_LENGTH 32

#define XATTR_ACCEPTED_SIGNAL 359
#define XATTR_REJECTED_SIGNAL 360

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

#endif /* TRM_SHARED_DEFINITIONS_H_ */
