#include <key_mgmt.h>
#include "utils.h"

static vhsm_key_id TEST_KEY_ID = {"test_key"};

bool enum_keys(vhsm_session session) {
    unsigned int key_count = 0;
    vhsm_rv rv = vhsm_key_mgmt_get_key_info(session, NULL, &key_count);
    if(VHSM_RV_OK != rv) return false;

    vhsm_key_info *keys_info = new vhsm_key_info[key_count];
    rv = vhsm_key_mgmt_get_key_info(session, keys_info, &key_count);
    if (rv != VHSM_RV_OK) {
        delete[] keys_info;
        return false;
    }

    std::cout << "All keys" << std::endl;
    for(unsigned int i = 0; i < key_count; ++i) {
        std::cout << keys_info[i].key_id.id
                  << " | length: " << keys_info[i].length
                  << " | purpose: " << keys_info[i].purpose
                  << " | import date: " << keys_info[i].import_date
                  << std::endl;
    }
    delete[] keys_info;

    std::cout << "Single key: " << TEST_KEY_ID.id << std::endl;
    vhsm_key_info info;
    rv = vhsm_key_mgmt_get_key_info(session, TEST_KEY_ID, &info);
    if(rv != VHSM_RV_OK) return false;

    std::cout << info.key_id.id
              << " | length: " << info.length
              << " | purpose: " << info.purpose
              << " | import date: " << info.import_date
              << std::endl;

    return true;
}

int main(int argc, char ** argv) {
  vhsm_session session;
  
  
  if (start_session(session) != VHSM_RV_OK) {
    return 1;
  }
   
  if(!enum_keys(session)) {
    std::cerr << "test enum keys failed" << std::endl;
  } else {
    std::cerr << "test enum keys succeeded" << std::endl;
  }

  if (close_session(session) != VHSM_RV_OK) {
    return 1;
  } 
  
  return 0;
}
