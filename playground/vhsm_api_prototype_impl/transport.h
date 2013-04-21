#include <vhsm_api_prototype/common.h>
#include <vhsm_api_prototype/digest.h>
#include <vhsm_api_prototype/mac.h>

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

vhsm_rv vhsm_tr_mac_init_hmac_sha1(vhsm_session session);

vhsm_rv vhsm_tr_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size);

vhsm_rv vhsm_tr_mac_get_size(vhsm_session session, unsigned int * mac_size);

vhsm_rv vhsm_tr_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int mac_size);
