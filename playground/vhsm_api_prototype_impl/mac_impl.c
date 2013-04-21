#include <vhsm_api_prototype/mac.h>
#include <vhsm_api_prototype/digest.h>

//implemented in digest_impl.c
int is_valid_digest_method(vhsm_digest_method method);

int is_valid_mac_method(vhsm_mac_method method) {
  switch (method.mac_method) {
  case VHSM_MAC_HMAC : {
    return is_valid_digest_method(*((vhsm_digest_method *) method.method_params));
  }
  default : {
    return 0;
  }
  }
}

// Initializes a new mac computation.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_MAC_INIT_ERR, VHSM_RV_BAD_ARGUMENTS,
//             VHSM_RV_BAD_MAC_METHOD
vhsm_rv vhsm_mac_init(vhsm_session session, vhsm_mac_method method) {
  if (!is_valid_mac_method(method)) {
    return VHSM_RV_BAD_MAC_METHOD;
  }
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}

// Continues mac computation with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  if (0 == data_chunk && 0 != chunk_size) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}

// Ends mac computation. The computed code is stored in buffer pointed to by mac_ptr.
// A value pointed to by mac_size_ptr is updated to represent actual mac size.
// If a value pointed to by mac_size_ptr is greater than or equal to actual mac size,
// the mac is copied to the location pointed to by mac_ptr.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED,
//             VHSM_RV_BAD_BUFFER_SIZE, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int * mac_size_ptr) {
  if (0 == mac_size_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}
