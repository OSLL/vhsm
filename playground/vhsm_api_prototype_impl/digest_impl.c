#include <vhsm_api_prototype/digest.h>

int is_valid_digest_method(vhsm_digest_method method) {
  switch (method.digest_method) {
  case VHSM_DIGEST_SHA1 : {
    //TODO ensure parameters are valid.
    return 0 == method.method_params;
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
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}

// Continues digesting with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  if (0 == data_chunk && 0 != chunk_size) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  //TODO call some transport function
  
  return VHSM_RV_OK;
}

// Continues digesting with a key identified by passed key id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_KEY_NOT_FOUND
vhsm_rv vhsm_digest_key(vhsm_session session, vhsm_key_id key_id) {
  //TODO call some transport function
  return VHSM_RV_OK;
}

// Ends digesting operation. The computed digest is stored in buffer pointed to by digest_ptr.
// A value pointed to by digest_size_ptr is updated to represent actual digest size.
// If a value pointed to by digest_size_ptr is greater than or equal to actual digest size,
// the digest is copied to the location pointed to by digest_ptr.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_BAD_BUFFER_SIZE, VHSM_RV_BAD_BUFFER_SIZE
vhsm_rv vhsm_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int * digest_size_ptr) {
  if (0 == digest_size_ptr) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  
  //TODO call some transport function: determine size, if buffer is big enough request the data and copy it here else return
  
  return VHSM_RV_OK;
}
