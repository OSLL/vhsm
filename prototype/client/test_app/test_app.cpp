#include <iostream>
#include <digest.h>
#include <mac.h>
#include <key_mgmt.h>
#include <cstdio>

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

    std::cout << "Single key" << std::endl;
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
  vhsm_credentials credentials = {"user", "password"};
  
  if (VHSM_RV_OK != vhsm_start_session(&session)) {
    std::cerr << "failed to start session" << std::endl;
    return 1;
  }
  
  if (VHSM_RV_OK != vhsm_login(session, credentials)) {
    std::cerr << "failed to login" << std::endl;
    return 1;
  }
  
  
  if (!test_digest(session)) {
    std::cerr << "test digest failed" << std::endl;
  } else {
    std::cerr << "test digest succeeded" << std::endl;
  }
  
  if (!create_key(session)) {
    std::cerr << "failed to create a test key" << std::endl;
  } else {
    std::cerr << "test key creation succeeded" << std::endl;
  }
  
  if (!test_hmac(session)) {
    std::cerr << "test hmac failed" << std::endl;
  } else {
    std::cerr << "test hmac succeeded" << std::endl;
  }
  
  if(!enum_keys(session)) {
    std::cerr << "test enum keys failed" << std::endl;
  } else {
    std::cerr << "test enum keys succeeded" << std::endl;
  }

  if (VHSM_RV_OK != vhsm_logout(session)) {
    std::cerr << "failed to logout" << std::endl;
    return 1;
  }
  
  if (VHSM_RV_OK != vhsm_end_session(session)) {
    std::cerr << "failed to end session" << std::endl;
    return 1;
  }
  
  return 0;
}
