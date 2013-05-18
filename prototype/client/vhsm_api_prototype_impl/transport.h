#pragma once

#include <vhsm_api_prototype/common.h>
#include <vhsm_api_prototype/digest.h>
#include <vhsm_api_prototype/mac.h>
#include <vhsm_api_prototype/key_mgmt.h>

//
// common functions
//

vhsm_rv vhsm_tr_start_session(vhsm_session * session_ptr);

vhsm_rv vhsm_tr_end_session(vhsm_session session);

vhsm_rv vhsm_tr_login(vhsm_session session, vhsm_credentials credentials);

vhsm_rv vhsm_tr_logout(vhsm_session session);


//
// digest functions
//

vhsm_rv vhsm_tr_digest_init_sha1(vhsm_session session);

vhsm_rv vhsm_tr_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size);

vhsm_rv vhsm_tr_digest_key(vhsm_session session, vhsm_key_id key_id);

vhsm_rv vhsm_tr_digest_get_size(vhsm_session session, unsigned int * mac_size);

vhsm_rv vhsm_tr_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int digest_size);


//
// MAC functions
//

vhsm_rv vhsm_tr_mac_init_hmac_sha1(vhsm_session session, vhsm_key_id key_id);

vhsm_rv vhsm_tr_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size);

vhsm_rv vhsm_tr_mac_get_size(vhsm_session session, unsigned int * mac_size);

vhsm_rv vhsm_tr_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int mac_size);

//
// key management functions
//

vhsm_rv vhsm_tr_key_mgmt_get_key_ids_count(vhsm_session session, unsigned int * ids_count);

vhsm_rv vhsm_tr_key_mgmt_get_key_ids(vhsm_session session, vhsm_key_id * ids, unsigned int ids_count);

vhsm_rv vhsm_tr_key_mgmt_delete_key(vhsm_session session, vhsm_key_id key_id);

vhsm_rv vhsm_tr_key_mgmt_create_key(vhsm_session session, vhsm_key key);
