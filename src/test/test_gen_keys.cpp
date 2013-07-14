#include <key_mgmt.h>
#include "utils.h"

bool gen_keys(vhsm_session session) {
    vhsm_key_id id1 = {"123"};
    vhsm_rv rv = vhsm_key_mgmt_generate_key(session, &id1);
    if(rv == VHSM_RV_OK) {
        std::cout << "Generated key with specified id " << id1.id << std::endl;
    } else return false;

    vhsm_key_id id2 = {"\0"};
    rv = vhsm_key_mgmt_generate_key(session, &id2);
    if(rv == VHSM_RV_OK) {
        std::cout << "Generated key with generated id " << id2.id << std::endl;
    } else return false;

    return true;
}

int main(int argc, char ** argv) {
  vhsm_session session;
  
  
  if (start_session(session) != VHSM_RV_OK) {
    return 1;
  }
   
  if(!gen_keys(session)) {
    std::cerr << "keys generation failed" << std::endl;
  } else {
    std::cerr << "keys generation succeeded" << std::endl;
  }

  if (close_session(session) != VHSM_RV_OK) {
    return 1;
  } 
  
  return 0;
}
