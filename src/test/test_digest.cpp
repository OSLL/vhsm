#include "utils.h"

bool test_digest(vhsm_session session) {
  vhsm_rv rv = VHSM_RV_OK;
  vhsm_digest_method sha1 = {VHSM_DIGEST_SHA1, (void *)0};
  unsigned char message[] = "";
  
  rv = vhsm_digest_init(session, sha1);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_digest_init() failed" << std::endl;
    return false;
  }
  
  rv = vhsm_digest_update(session, message, sizeof(message) - 1);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_digest_update() failed" << std::endl;
    return false;
  }
  
  unsigned int digest_size = 0;
  
  rv = vhsm_digest_end(session, 0, &digest_size);
  if (VHSM_RV_BAD_BUFFER_SIZE != rv) {
    std::cerr << "vhsm_digest_end(): failed to obtain digest size" << std::endl;
    return false;
  }
  
  unsigned char *digest = new unsigned char[digest_size + 1];
  
  rv = vhsm_digest_end(session, digest, &digest_size);
  if (VHSM_RV_OK != rv) {
    std::cerr << "vhsm_digest_end(): failed to obtain digest" << std::endl;
    return false;
  }
  
  digest[digest_size] = '\0';
  std::cout << "digest of an empty string is: ";
  print_bytes(digest, digest_size);
  std::cout << std::endl;
  
  return true;
}

int main(int argc, char ** argv) {
  vhsm_session session;
  
  
  if (start_session(session) != VHSM_RV_OK) {
    return 1;
  }
   
  if (!test_digest(session)) {
    std::cerr << "test digest failed" << std::endl;
  } else {
    std::cerr << "test digest succeeded" << std::endl;
  }

  if (close_session(session) != VHSM_RV_OK) {
    return 1;
  } 
  
  return 0;
}
