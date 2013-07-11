#include <key_mgmt.h>
#include "utils.h"

static vhsm_key_id TEST_KEY_ID = {"test_key"};

bool create_key(vhsm_session session) {
  static vhsm_key TEST_KEY = {TEST_KEY_ID, (void *) 0, 0};
  
  vhsm_rv rv = VHSM_RV_OK;
  
  rv = vhsm_key_mgmt_create_key(session, TEST_KEY);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_key_mgmt_create_key(): failed to import a key" << std::endl;
    return false;
  }
  
  return true;
}

int main(int argc, char ** argv) {
  vhsm_session session;
  
  
  if (start_session(session) != VHSM_RV_OK) {
    return 1;
  }
   
  if (!create_key(session)) {
    std::cerr << "failed to create a test key" << std::endl;
  } else {
    std::cerr << "test key creation succeeded" << std::endl;
  }

  if (close_session(session) != VHSM_RV_OK) {
    return 1;
  } 
  
  return 0;
}
