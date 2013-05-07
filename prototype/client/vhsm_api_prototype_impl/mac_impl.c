#include <vhsm_api_prototype/mac.h>
#include <vhsm_api_prototype/digest.h>

#include "transport.h"

//implemented in digest_impl.c
int is_valid_digest_method(vhsm_digest_method method);



static vhsm_rv vhsm_mac_init_hmac(vhsm_session session, vhsm_digest_method const * digest_method_ptr) {
  if (0 == digest_method_ptr || !is_valid_digest_method(*digest_method_ptr)) {
    return VHSM_RV_BAD_MAC_METHOD;
  }
  
  switch (digest_method_ptr->digest_method) {
  case VHSM_DIGEST_SHA1 : {
    return vhsm_tr_mac_init_hmac_sha1(session);
  }
  default : {
    return VHSM_RV_BAD_MAC_METHOD;
  }
  }
}

// Initializes a new mac computation.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_MAC_INIT_ERR, VHSM_RV_BAD_ARGUMENTS,
//             VHSM_RV_BAD_MAC_METHOD
vhsm_rv vhsm_mac_init(vhsm_session session, vhsm_mac_method method) {
  switch (method.mac_method) {
  case VHSM_MAC_HMAC : {
    return vhsm_mac_init_hmac(session, (vhsm_digest_method const *) method.method_params);
  }
  default : {
    return VHSM_RV_BAD_MAC_METHOD;
  }
  }
}

// Continues mac computation with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  if (0 == data_chunk && 0 != chunk_size) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  return vhsm_tr_mac_update(session, data_chunk, chunk_size);
}

// Ends mac computation. The computed code is stored in buffer pointed to by mac_ptr.
// A value pointed to by mac_size_ptr is updated to represent actual mac size.
// If a value pointed to by mac_size_ptr is greater than or equal to actual mac size,
// the mac is copied to the location pointed to by mac_ptr. If it is less than actual size,
// the mac_size is updated and VHSM_RV_BAD_BUFFER_SIZE is returned.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED,
//             VHSM_RV_BAD_BUFFER_SIZE, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int * mac_size_ptr) {
  unsigned int mac_size = 0;
  vhsm_rv rv = VHSM_RV_OK;
  
  if (0 == mac_size_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  rv = vhsm_tr_mac_get_size(session, &mac_size);
  if (VHSM_RV_OK != rv) {
    return rv;
  }
  
  if (0 != mac_ptr && *mac_size_ptr >= mac_size) {
    //allright, we're ready to fetch the mac.
    rv = vhsm_tr_mac_end(session, mac_ptr, mac_size);
  } else {
    rv = VHSM_RV_BAD_BUFFER_SIZE;
  }
  
  *mac_size_ptr = mac_size;
  
  return rv;
}
