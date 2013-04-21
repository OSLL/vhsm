//
// This file contains definitions for message authentication code (mac) computation
//

#pragma once

#include "common.h"

typedef int vhsm_mac_method_id;

// HMAC algorithm. If this value is used in vhsm_mac_method struct
// then struct's method_params should point to a valid vhsm_digest_method struct.
#define VHSM_MAC_HMAC 0x00000001

// mac method
typedef struct {
  // one of VHSM_MAC_* constants
  vhsm_mac_method_id mac_method;
  // method-specific params
  void * method_params;
  // key for mac computation
  vhsm_key_id key_id;
} vhsm_mac_method;


// Initializes a new mac computation.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED,
//             VHSM_RV_MAC_INIT_ERR, VHSM_RV_BAD_ARGUMENTS,
//             VHSM_RV_BAD_MAC_METHOD
vhsm_rv vhsm_mac_init(vhsm_session session, vhsm_mac_method method);

// Continues mac computation with passed data chunk.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size);

// Ends mac computation. The computed code is stored in buffer pointed to by mac_ptr.
// A value pointed to by mac_size_ptr is updated to represent actual mac size.
// If a value pointed to by mac_size_ptr is greater than or equal to actual mac size,
// the mac is copied to the location pointed to by mac_ptr.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_MAC_NOT_INITIALIZED,
//             VHSM_RV_BAD_BUFFER_SIZE, VHSM_RV_BAD_ARGUMENTS
vhsm_rv vhsm_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int * mac_size_ptr);
