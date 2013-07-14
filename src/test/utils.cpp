#include "utils.h"

int start_session(vhsm_session& session) {
  vhsm_credentials credentials = {"user", "password"};
  
  if (VHSM_RV_OK != vhsm_start_session(&session)) {
    std::cerr << "failed to start session" << std::endl;
    return 1;
  }
  
  if (VHSM_RV_OK != vhsm_login(session, credentials)) {
    std::cerr << "failed to login" << std::endl;
    return 1;
  }
  
  return VHSM_RV_OK;
}

int close_session (vhsm_session& session) {
  if (VHSM_RV_OK != vhsm_logout(session)) {
    std::cerr << "failed to logout" << std::endl;
    return 1;
  }
  
  if (VHSM_RV_OK != vhsm_end_session(session)) {
    std::cerr << "failed to end session" << std::endl;
    return 1;
  }
  
  return VHSM_RV_OK;
}

void print_bytes(unsigned char const * data, size_t n_bytes) {
  size_t i = 0;
  
  printf("0x");
  
  if (0 == n_bytes) {
    printf("0");
    return;
  }
  
  for (i = 0; i != n_bytes; ++i) {
    printf("%.2x", (int) data[i]);
  }
}
