//
// This file contains definitions of all basic types, structures, functions, error codes, etc
//


#pragma once

#include <stdint.h>

#include "vhsm_transport.pb.h"

//
// error handling
//

// A return type for all functions requiring error handling
typedef ErrorCode vhsm_rv;

#define VHSM_MAX_DATA_LENGTH 3072

//
// sessions and identification
//

// session info type
typedef struct {
  long sid;
} vhsm_session;

// credentials
typedef struct {
  char username[64];
  char password[64];
} vhsm_credentials;

// Start a new session. Session structure pointed to by session_ptr is initialized if this call succeeds.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_start_session(vhsm_session * session_ptr);

// End session.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_end_session(vhsm_session session);

// Attempt to login.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_CREDENTIALS
vhsm_rv vhsm_login(vhsm_session session, vhsm_credentials credentials);

// Logout
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_logout(vhsm_session session);



//
// keys
//

// key identificator
typedef struct {
  unsigned char id[128];
} vhsm_key_id;

typedef struct {
    vhsm_key_id key_id;
    int purpose;
    uint32_t length;
    uint64_t import_date;
} vhsm_key_info;
