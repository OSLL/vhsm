#include <vhsm_api_prototype/common.h>

#include "transport.h"

// Start a new session. Session structure pointed to by session_ptr is initialized if this call succeeds.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_start_session(vhsm_session * session_ptr) {
  if (0 == session_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  return vhsm_tr_start_session(session_ptr);
}

// End session.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_end_session(vhsm_session session) {
  return vhsm_tr_end_session(session);
}

// Attempt to login.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_CREDENTIALS
vhsm_rv vhsm_login(vhsm_session session, vhsm_credentials credentials) {
  return vhsm_tr_login(session, credentials);
}

// Logout
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_logout(vhsm_session session) {
  return vhsm_tr_logout(session);
}
