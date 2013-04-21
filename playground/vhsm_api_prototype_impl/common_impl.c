#include <vhsm_api_prototype/common.h>

// Start a new session. Session structure pointed to by session_ptr is initialized if this call succeeds.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_start_session(vhsm_session * session_ptr) {
  if (0 == session_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}

// End session.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_end_session(vhsm_session session) {
  //TODO call some transport function
  return VHSM_RV_OK;
}

// Attempt to login.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_BAD_CREDENTIALS
vhsm_rv vhsm_login(vhsm_session session, vhsm_credentials credentials) {
  //TODO call some transport function
  return VHSM_RV_OK;
}

// Logout
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION
vhsm_rv vhsm_logout(vhsm_session session) {
  //TODO call some transport function
  return VHSM_RV_OK;
}
