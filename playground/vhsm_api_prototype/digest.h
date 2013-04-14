//
// This file contains definitions required for digesting functions
//


#pragma once

#include "common.h"


// digest method identificator
typedef int vhsm_digest_method_id;

#define VHSM_DIGEST_SHA1 0x00000001

// digest method
typedef struct {
  // one of VHSM_DIGEST_* constants
  vhsm_digest_method_id digest_method;
  // method-specific params or 0 if method does not require params
  void * method_params;
} vhsm_digest_method;


// Initializes a new digesting operation.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_BAD_DIGEST_METHOD, VHSM_DIGEST_INIT_ERR
vhsm_rv vhsm_digest_init(vhsm_session session, vhsm_digest_method method);

// Continues digesting with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED
vhsm_rv vhsm_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size);

// Continues digesting with a key identified by passed key id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_KEY_NOT_FOUND
vhsm_rv vhsm_digest_key(vhsm_session session, vhsm_key_id key_id);

// Ends digesting operation. The computed digest is stored in buffer pointed to by digest_ptr.
// A value pointed to by digest_size_ptr is updated to represent actual digest size.
// If a value pointed to by digest_size_ptr is greater than or equal to actual digest size,
// the digest is copied to the location pointed to by digest_ptr.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_DIGEST_NOT_INITIALIZED, VHSM_RV_BAD_BUFFER_SIZE
vhsm_rv vhsm_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int * digest_size_ptr);
