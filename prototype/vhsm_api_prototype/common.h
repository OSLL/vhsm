//
// This file contains definitions of all basic types, structures, functions, error codes, etc
//


#pragma once


//
// error handling
//

// A return type for all functions requiring error handling
typedef int vhsm_rv;

// error constants

// successful function call
#define VHSM_RV_OK 0x0

// passed buffer's size is less than required
#define VHSM_RV_BAD_BUFFER_SIZE 0x00000009
// bad arguments
#define VHSM_RV_BAD_ARGUMENTS 0x0000000C

// bad session
#define VHSM_RV_BAD_SESSION 0x00000001
// authenticated user is not authorized to permit an operation
#define VHSM_RV_NOT_AUTHORIZED 0x00000003
// authentication failed due to bad credentials
#define VHSM_RV_BAD_CREDENTIALS 0x00000002

// illegal digest method passed to a function
#define VHSM_RV_BAD_DIGEST_METHOD 0x00000005

// digest init function failed
#define VHSM_RV_DIGEST_INIT_ERR 0x00000006
// digest_update or digest_end were called prior to digest_init
#define VHSM_RV_DIGEST_NOT_INITIALIZED 0x00000007

// key with passed key_id was not found
#define VHSM_RV_KEY_NOT_FOUND 0x00000008

//illegal mac method passed to a function
#define VHSM_RV_BAD_MAC_METHOD 0x0000000D

// mac init function failed
#define VHSM_RV_MAC_INIT_ERR 0x0000000A
// mac_update or mac_end were called prior to mac_init
#define VHSM_RV_MAC_NOT_INITIALIZED 0x0000000B

//
// sessions and identification
//

// session info type
typedef struct {
  long sid;
} vhsm_session;

// credentials info type (stub)
typedef struct {
  // it is not clear yet what kind of credentials should be used - using a stub.
  char __dummy__;
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
