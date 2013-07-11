#include <mac.h>
#include "utils.h"

static vhsm_key_id TEST_KEY_ID = {"test_key"};

bool test_hmac(vhsm_session session) {
  vhsm_rv rv = VHSM_RV_OK;
  vhsm_digest_method sha1 = {VHSM_DIGEST_SHA1, (void *)0};
  vhsm_mac_method hmac_sha1 = {VHSM_MAC_HMAC, &sha1, TEST_KEY_ID};
  unsigned char message[] = "";
  
  rv = vhsm_mac_init(session, hmac_sha1);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_mac_init(): failed" << std::endl;
    return false;
  }
  
  rv = vhsm_mac_update(session, message, sizeof(message) - 1);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_mac_update(): failed" << std::endl;
  }
  
  unsigned int hmac_size = 0;
  
  rv = vhsm_mac_end(session, (unsigned char *)0, &hmac_size);
  if (VHSM_RV_BAD_BUFFER_SIZE != rv) {
    std::cerr << "vhsm_mac_end(): failed to obtain mac size" << std::endl;
    return false;
  }
  
  unsigned char * mac = new unsigned char[hmac_size + 1];
  
  rv = vhsm_mac_end(session, mac, &hmac_size);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_mac_end(): failed to obtain mac" << std::endl;
    delete [] mac;
    return false;
  }
  
  mac[hmac_size] = '\0';
  
  std::cout << "hmac-sha1 of an empty string with an empty key is: ";
  print_bytes(mac, hmac_size);
  std::cout << std::endl;
  
  delete [] mac;
  
  return true;
}


int main(int argc, char ** argv) {
  vhsm_session session;
  
  
  if (start_session(session) != VHSM_RV_OK) {
    return 1;
  }
   
  if (!test_hmac(session)) {
    std::cerr << "test hmac failed" << std::endl;
  } else {
    std::cerr << "test hmac succeeded" << std::endl;
  }

  if (close_session(session) != VHSM_RV_OK) {
    return 1;
  } 
  
  return 0;
}
