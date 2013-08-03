#include <vhsm_api_prototype/key_mgmt.h>

#include "transport.h"
#include "string.h"


// List available key ids. Ids are written to buffer pointed to by 'ids' argument.
// If 'ids' is not NULL, 'ids_count' represent maximum count of key ids which can be written to buffer.
// After the call 'ids_count' is updated to actual written ids count.
// If called with NULL passed as 'ids', VHSM_RV_BAD_BUFFER_SIZE is returned and ids_count is updated appropriately.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_BAD_BUFFER_SIZE
vhsm_rv vhsm_key_mgmt_get_key_ids(vhsm_session session, vhsm_key_id * ids, unsigned int * ids_count_ptr) {
  vhsm_rv rv = VHSM_RV_OK;
  unsigned int ids_count = 0;
  
  /*
  if (0 == ids_count) {
    return VHSM_RV_BAD_ARGUMENTS;
  }
  */
  
  rv = vhsm_tr_key_mgmt_get_key_ids_count(session, &ids_count);
  if (VHSM_RV_OK != rv) {
    return rv;
  }
  
  if (0 != ids && *ids_count_ptr >= ids_count) {
    rv = vhsm_tr_key_mgmt_get_key_ids(session, ids, ids_count);
  } else {
    rv = VHSM_RV_BAD_BUFFER_SIZE;
  }
  
  *ids_count_ptr = ids_count;
  
  return rv;
}

// Deletes a secret object identified by passed id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_KEY_NOT_FOUND
vhsm_rv vhsm_key_mgmt_delete_key(vhsm_session session, vhsm_key_id key_id) {
  return vhsm_tr_key_mgmt_delete_key(session, key_id);
}

// Uploads passed secret object to vhsm. The object is then accessible with passed vhsm_key_id.
// Can return: VHSM_RV_OK, VHSM_RV_BAD_SESSION, VHSM_RV_NOT_AUTHORIZED, VHSM_RV_KEY_ID_OCCUPIED
vhsm_rv vhsm_key_mgmt_create_key(vhsm_session session, vhsm_key key, int purpose) {
    vhsm_key_id key_id;
    return vhsm_tr_key_mgmt_import_key(session, key, purpose, true, &key_id);
}

vhsm_rv vhsm_key_mgmt_create_key(vhsm_session session, vhsm_key key, vhsm_key_id *key_id, int purpose) {
    return vhsm_tr_key_mgmt_import_key(session, key, purpose, true, key_id);
}

vhsm_rv vhsm_key_mgmt_generate_key(vhsm_session session, vhsm_key_id *key_id, unsigned int key_length, int purpose) {
    vhsm_key key;
    key.key_data = NULL;
    key.data_size = 0;
    memcpy(key.id.id, key_id->id, sizeof(key_id->id));
    return vhsm_tr_key_mgmt_import_key(session, key, purpose, false, key_id);
}

vhsm_rv vhsm_key_mgmt_get_key_info(vhsm_session session, vhsm_key_info *keys, unsigned int *keys_count_ptr) {
    vhsm_rv rv = VHSM_RV_OK;
    unsigned int keys_count = 0;

    rv = vhsm_tr_key_mgmt_get_key_ids_count(session, &keys_count);

    if(!keys) {
        if(rv != VHSM_RV_OK) return rv;
    } else if(*keys_count_ptr >= keys_count) {
        vhsm_key_id id;
        memset(id.id, 0, sizeof(id.id));
        rv = vhsm_tr_key_mgmt_get_key_info(session, keys, keys_count, id);
    } else {
        rv = VHSM_RV_BAD_BUFFER_SIZE;
    }

    *keys_count_ptr = keys_count;
    return rv;
}

vhsm_rv vhsm_key_mgmt_get_key_info(vhsm_session session, vhsm_key_id key_id, vhsm_key_info *info) {
    return vhsm_tr_key_mgmt_get_key_info(session, info, 1, key_id);
}
