#pragma once

#include "common.h"

typedef struct {
  vhsm_key_id id;
  void * key_data;
  unsigned int data_size;
} vhsm_key;


// List available key ids. Ids are written to buffer pointed to by 'ids' argument.
// If 'ids' is not NULL, 'ids_count' represent maximum count of key ids which can be written to buffer.
// After the call 'ids_count' is updated to actual written ids count.
// If called with NULL passed as 'ids', VHSM_RV_BAD_BUFFER_SIZE is returned and ids_count is updated appropriately.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_BAD_BUFFER_SIZE
vhsm_rv vhsm_key_mgmt_get_key_ids(vhsm_session session, vhsm_key_id * ids, unsigned int * ids_count);


// Deletes a secret object identified by passed id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_KEY_NOT_FOUND
vhsm_rv vhsm_key_mgmt_delete_key(vhsm_session session, vhsm_key_id key_id);

// Uploads passed secret object to vhsm. The object is then accessible with passed vhsm_key_id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_KEY_ID_OCCUPIED
vhsm_rv vhsm_key_mgmt_create_key(vhsm_session session, vhsm_key key);
