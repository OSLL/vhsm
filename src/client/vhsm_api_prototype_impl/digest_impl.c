#include <vhsm_api_prototype/digest.h>

#include "transport.h"

int is_valid_sha1_params(void * params) {
  return 0 == params;
}

int is_valid_digest_method(vhsm_digest_method method) {
  switch (method.digest_method) {
  case VHSM_DIGEST_SHA1 : {
    return is_valid_sha1_params(method.method_params);
  }
  default : {
    return 0;
  }
  }
}

// Initializes a new digesting operation.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_BAD_DIGEST_METHOD, VHSM_DIGEST_INIT_ERR
vhsm_rv vhsm_digest_init(vhsm_session session, vhsm_digest_method method) {
  if (!is_valid_digest_method(method)) {
    return VHSM_RV_BAD_DIGEST_METHOD;
  }
  
  switch (method.digest_method) {
  case VHSM_DIGEST_SHA1 : {
    return vhsm_tr_digest_init_sha1(session);
  }
  default : {
    return VHSM_RV_BAD_DIGEST_METHOD;
  }
  }
}

// Continues digesting with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  if (0 == data_chunk && 0 != chunk_size) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  return vhsm_tr_digest_update(session, data_chunk, chunk_size);
}

// Continues digesting with a key identified by passed key id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_KEY_NOT_FOUND
vhsm_rv vhsm_digest_key(vhsm_session session, vhsm_key_id key_id) {
  return vhsm_tr_digest_key(session, key_id);
}

// Ends digesting operation. The computed digest is stored in buffer pointed to by digest_ptr.
// A value pointed to by digest_size_ptr is updated to represent actual digest size.
// If a value pointed to by digest_size_ptr is greater than or equal to actual digest size,
// the digest is copied to the location pointed to by digest_ptr.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_BAD_BUFFER_SIZE, VHSM_RV_BAD_BUFFER_SIZE
vhsm_rv vhsm_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int * digest_size_ptr) {
  unsigned int digest_size = 0;
  vhsm_rv rv = VHSM_RV_OK;
  
  if (0 == digest_size_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  rv = vhsm_tr_digest_get_size(session, &digest_size);
  if (VHSM_RV_OK != rv) {
    return rv;
  }
  
  if (0 != digest_ptr && *digest_size_ptr >= digest_size) {
    rv = vhsm_tr_digest_end(session, digest_ptr, digest_size);
  } else {
    rv = VHSM_RV_BAD_BUFFER_SIZE;
  }
  
  *digest_size_ptr = digest_size;
  
  return rv;
}
