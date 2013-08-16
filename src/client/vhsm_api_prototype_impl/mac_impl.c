#include <vhsm_api_prototype/mac.h>
#include <vhsm_api_prototype/digest.h>

#include "transport.h"

//implemented in digest_impl.c
int is_valid_digest_method(vhsm_digest_method method);



static vhsm_rv vhsm_mac_init_hmac(vhsm_session session, vhsm_digest_method const * digest_method_ptr, vhsm_key_id key_id) {
  if (0 == digest_method_ptr || !is_valid_digest_method(*digest_method_ptr)) {
    return ERR_BAD_MAC_METHOD;
  }
  
  switch (digest_method_ptr->digest_method) {
  case VHSM_DIGEST_SHA1 : {
    return vhsm_tr_mac_init_hmac_sha1(session, key_id);
  }
  default : {
    return ERR_BAD_MAC_METHOD;
  }
  }
}

// Initializes a new mac computation.
// Can return: ERR_NO_ERROR, ERR_BAD_SESSION, ERR_NOT_AUTHORIZED,
//             ERR_MAC_INIT, ERR_BAD_ARGUMENTS,
//             ERR_BAD_MAC_METHOD
vhsm_rv vhsm_mac_init(vhsm_session session, vhsm_mac_method method) {
  switch (method.mac_method) {
  case VHSM_MAC_HMAC : {
    return vhsm_mac_init_hmac(session, (vhsm_digest_method const *) method.method_params, method.key_id);
  }
  default : {
    return ERR_BAD_MAC_METHOD;
  }
  }
}

// Continues mac computation with passed data chunk.
// Can return: ERR_NO_ERROR, ERR_BAD_SESSION, ERR_NOT_AUTHORIZED, ERR_MAC_NOT_INITIALIZED, ERR_BAD_ARGUMENTS
vhsm_rv vhsm_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  if (0 == data_chunk && 0 != chunk_size) {
    return ERR_BAD_ARGUMENTS;
  }
  
  return vhsm_tr_mac_update(session, data_chunk, chunk_size);
}

// Ends mac computation. The computed code is stored in buffer pointed to by mac_ptr.
// A value pointed to by mac_size_ptr is updated to represent actual mac size.
// If a value pointed to by mac_size_ptr is greater than or equal to actual mac size,
// the mac is copied to the location pointed to by mac_ptr. If it is less than actual size,
// the mac_size is updated and ERR_BAD_BUFFER_SIZE is returned.
// Can return: ERR_NO_ERROR, ERR_BAD_SESSION, ERR_NOT_AUTHORIZED, ERR_MAC_NOT_INITIALIZED,
//             ERR_BAD_BUFFER_SIZE, ERR_BAD_ARGUMENTS
vhsm_rv vhsm_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int * mac_size_ptr) {
  unsigned int mac_size = 0;
  vhsm_rv rv = ERR_NO_ERROR;
  
  if (0 == mac_size_ptr) {
    return ERR_BAD_ARGUMENTS;
  }
  
  rv = vhsm_tr_mac_get_size(session, &mac_size);
  if (ERR_NO_ERROR != rv) {
    return rv;
  }
  
  if (0 != mac_ptr && *mac_size_ptr >= mac_size) {
    //allright, we're ready to fetch the mac.
    rv = vhsm_tr_mac_end(session, mac_ptr, mac_size);
  } else {
    rv = ERR_BAD_BUFFER_SIZE;
  }
  
  *mac_size_ptr = mac_size;
  
  return rv;
}
