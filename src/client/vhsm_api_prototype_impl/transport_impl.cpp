#include <algorithm>
#include "vhsm_transport.pb.h"

#include "VhsmMessageTransport.h"

static VhsmMessageTransport transport;

static bool send_message(const VhsmMessage &message, VhsmResponse &response) {
    if(!transport.is_open()) return false;

    bool result = false;
    size_t msg_buf_size = message.ByteSize();
    char *msg_buf = new char[msg_buf_size];

    char rsp_buf[MAX_MSG_SIZE];
    size_t rsp_buf_size = MAX_MSG_SIZE;
    vmsghdr *msgh = 0;

    if(!message.SerializeToArray(msg_buf, msg_buf_size)) goto cleanup;
    if(!transport.send_data(msg_buf, msg_buf_size, VHSM_REQUEST)) goto cleanup;
    if(!transport.receive_data(rsp_buf, &rsp_buf_size)) goto cleanup;

    msgh = (vmsghdr*)rsp_buf;
    if(msgh->type != VHSM_RESPONSE) goto cleanup;
    result = response.ParseFromArray(GET_MSG_DATA(rsp_buf), rsp_buf_size - sizeof(vmsghdr));

cleanup:
    delete[] msg_buf;
    return result;
}

//
//transport.h implementation
//

#include "transport.h"


//converts error code from one used in protobuf messages to VHSM_RV_* code.
/*static vhsm_rv convert_error_code(ErrorCode error) {
    switch(error) {
    case ERR_NO_ERROR : return VHSM_RV_OK;
    case ERR_BAD_ARGUMENTS : return VHSM_RV_BAD_ARGUMENTS;
    case ERR_BAD_SESSION : return VHSM_RV_BAD_SESSION;
    case ERR_BAD_DIGEST_METHOD : return VHSM_RV_BAD_DIGEST_METHOD;
    case ERR_DIGEST_INIT : return VHSM_RV_DIGEST_INIT_ERR;
    case ERR_DIGEST_NOT_INITIALIZED : return VHSM_RV_DIGEST_NOT_INITIALIZED;
    case ERR_KEY_NOT_FOUND : return VHSM_RV_KEY_NOT_FOUND;
    case ERR_BAD_MAC_METHOD : return VHSM_RV_BAD_MAC_METHOD;
    case ERR_MAC_INIT : return VHSM_RV_MAC_INIT_ERR;
    case ERR_MAC_NOT_INITIALIZED : return VHSM_RV_MAC_NOT_INITIALIZED;
    case ERR_BAD_CREDENTIALS : return VHSM_RV_BAD_CREDENTIALS;
    case ERR_KEY_ID_OCCUPIED : return VHSM_RV_KEY_ID_OCCUPIED;
    case ERR_NOT_AUTHORIZED : return VHSM_RV_NOT_AUTHORIZED;
    default : return VHSM_RV_ERR;
    }
}
*/
static vhsm_rv send_message_ok_response(VhsmMessage const & message, VhsmResponse & response) {
  if (!send_message(message, response)) {
    return ERR_VHSM_ERROR;
  }
  
  switch (response.type()) {
    case VhsmResponse::ERROR : return response.error_code();
    case VhsmResponse::OK : return ERR_NO_ERROR;
    default : return ERR_VHSM_ERROR;
  }
}

static vhsm_rv send_message_unsigned_int_response(VhsmMessage const & message,
                                                  VhsmResponse & response,
                                                  unsigned int * r) {
  if (!send_message(message, response)) {
    return ERR_VHSM_ERROR;
  }
  
  switch (response.type()) {
    case VhsmResponse::ERROR : return response.error_code();
    case VhsmResponse::UNSIGNED_INT : {
      if (!response.has_unsigned_int()) {
        return ERR_VHSM_ERROR;
      }
      *r = response.unsigned_int();
      return ERR_NO_ERROR;
    }
    default : return ERR_VHSM_ERROR;
  }
}

static vhsm_rv send_message_raw_data_response(VhsmMessage const & message,
                                              VhsmResponse & response,
                                              unsigned char * buf,
                                              unsigned int buf_sz) {
  if (!send_message(message, response)) {
    return ERR_VHSM_ERROR;
  }
  
  switch (response.type()) {
    case VhsmResponse::ERROR : return response.error_code();
    case VhsmResponse::RAW_DATA : {
      if (!response.has_raw_data()) {
        return ERR_VHSM_ERROR;
      }
      
      if (response.raw_data().data().size() > buf_sz) {
        return ERR_BAD_BUFFER_SIZE;
      }
      
      unsigned char const * data = (unsigned char const *) response.raw_data().data().data();
      std::copy(data, data + response.raw_data().data().size(), buf);
      
      return ERR_NO_ERROR;
    }
    default : return ERR_VHSM_ERROR;
  }
}

static vhsm_rv send_message_key_ids_response(VhsmMessage const & message,
                                             VhsmResponse & response,
                                             vhsm_key_id * key_ids,
                                             unsigned int ids_max) {
  if (!send_message(message, response)) {
    return ERR_VHSM_ERROR;
  }
  
  switch (response.type()) {
    case VhsmResponse::ERROR : return response.error_code();
    case VhsmResponse::KEY_ID_LIST : {
      if (!response.has_key_ids()) {
        return ERR_VHSM_ERROR;
      }
      
      KeyIdList const & fetched_ids_list = response.key_ids();
      
      if (fetched_ids_list.ids_size() > ids_max) {
        return ERR_BAD_BUFFER_SIZE;
      }
      
      for (int i = 0; i != fetched_ids_list.ids_size(); ++i) {
        VhsmKeyId const & kid = fetched_ids_list.ids(i);
        
        if (kid.id().size() + 1 > sizeof(vhsm_key_id::id)) {
          //this means vhsm's key_id length is greater than the length in this API.
          return ERR_VHSM_ERROR;
        }
        
        std::copy(kid.id().begin(), kid.id().end(), (key_ids + i)->id);
        (key_ids + i)->id[kid.id().size()] = 0;
      }
      
      return ERR_NO_ERROR;
    }
    default : return ERR_VHSM_ERROR;
  }
}

static vhsm_rv send_message_key_info_response(const VhsmMessage &message,
                                              VhsmResponse &response,
                                              vhsm_key_info *keys_info,
                                              unsigned int keys_count) {
    if(!send_message(message, response)) return ERR_VHSM_ERROR;

    switch(response.type()) {
    case VhsmResponse::ERROR: return response.error_code();
    case VhsmResponse::KEY_INFO_LIST: {
        if(!response.has_key_info()) return ERR_VHSM_ERROR;
        const KeyInfoList &info_list = response.key_info();
        if(info_list.keys_size() > keys_count) return ERR_BAD_BUFFER_SIZE;
        for (int i = 0; i != info_list.keys_size(); ++i) {
            const KeyInfo &ki = info_list.keys(i);
            if(ki.id().id().size() + 1 > sizeof(vhsm_key_id::id)) {
                //this means vhsm's key_id length is greater than the length in this API.
                return ERR_VHSM_ERROR;
            }

            vhsm_key_info *cki = keys_info + i;
            cki->length = ki.length();
            cki->purpose = ki.purpose();
            cki->import_date = ki.time();
            std::copy(ki.id().id().begin(), ki.id().id().end(), cki->key_id.id);
            cki->key_id.id[ki.id().id().size()] = 0;
        }
        return ERR_NO_ERROR;
    }
    default:
        return ERR_VHSM_ERROR;
    }
}

//
// common functions
//


static VhsmMessage create_session_message(VhsmSessionMessage_MessageType type, vhsm_session session) {
  VhsmMessage message;
  
  message.mutable_session()->
          set_sid(session.sid);
  
  message.set_message_class(SESSION);
  message.mutable_session_message()->
          set_type(type);
  
  return message;
}

vhsm_rv vhsm_tr_start_session(vhsm_session * session_ptr) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::START, *session_ptr);
  VhsmResponse response;
  
  if (!send_message(message, response)) {
    return ERR_VHSM_ERROR;
  }
  
  switch (response.type()) {
    case VhsmResponse::ERROR : return response.error_code();
    case VhsmResponse::SESSION : {
      if (!response.has_session()) {
        return ERR_VHSM_ERROR;
      }
      session_ptr->sid = response.session().sid();
      return ERR_NO_ERROR;
    }
    default : return ERR_VHSM_ERROR;
  }
}

vhsm_rv vhsm_tr_end_session(vhsm_session session) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::END, session);
  VhsmResponse response;
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_login(vhsm_session session, vhsm_credentials credentials) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::LOGIN, session);
  VhsmResponse response;
  
  message.mutable_session_message()->
          mutable_login_message()->
          set_username(credentials.username);
  message.mutable_session_message()->
          mutable_login_message()->
          set_password(credentials.password);
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_logout(vhsm_session session) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::LOGOUT, session);
  VhsmResponse response;
  
  return send_message_ok_response(message, response);
}


//
// digest functions
//

static VhsmMessage create_digest_message(VhsmDigestMessage_MessageType type, vhsm_session session) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  
  message.mutable_session()->
          set_sid(session.sid);
  message.mutable_digest_message()->
          set_type(type);
  
  return message;
}

vhsm_rv vhsm_tr_digest_init_sha1(vhsm_session session) {
  VhsmMessage message = create_digest_message(VhsmDigestMessage::INIT, session);
  VhsmResponse response;
  
  message.mutable_digest_message()->
          mutable_init_message()->
          mutable_mechanism()->
          set_mid(SHA1);
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  VhsmMessage message = create_digest_message(VhsmDigestMessage::UPDATE, session);
  VhsmResponse response;
  
  message.mutable_digest_message()->
          mutable_update_message()->
          mutable_data_chunk()->
          set_data(std::string((char const *)data_chunk, chunk_size));
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_digest_key(vhsm_session session, vhsm_key_id key_id) {
  VhsmMessage message = create_digest_message(VhsmDigestMessage::UPDATE_KEY, session);
  VhsmResponse response;
  
  message.mutable_digest_message()->
          mutable_update_key_message()->
          mutable_key_id()->
          set_id((void const *) key_id.id, sizeof(key_id.id));
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_digest_get_size(vhsm_session session, unsigned int * digest_size) {
  VhsmMessage message = create_digest_message(VhsmDigestMessage::GET_DIGEST_SIZE, session);
  VhsmResponse response;
  
  return send_message_unsigned_int_response(message, response, digest_size);
}

vhsm_rv vhsm_tr_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int digest_size) {
  VhsmMessage message = create_digest_message(VhsmDigestMessage::END, session);
  VhsmResponse response;
  
  return send_message_raw_data_response(message, response, digest_ptr, digest_size);
}


//
// MAC functions
//

static VhsmMessage create_mac_message(VhsmMacMessage_MessageType type, vhsm_session session) {
  VhsmMessage message;
  
  message.set_message_class(MAC);
  
  message.mutable_session()->
          set_sid(session.sid);
  message.mutable_mac_message()->
          set_type(type);
  
  return message;
}

vhsm_rv vhsm_tr_mac_init_hmac_sha1(vhsm_session session, vhsm_key_id key_id) {
  VhsmMessage message = create_mac_message(VhsmMacMessage::INIT, session);
  VhsmResponse response;
  
  message.mutable_mac_message()->
          mutable_init_message()->
          mutable_mechanism()->
          set_mid(HMAC);
  message.mutable_mac_message()->
          mutable_init_message()->
          mutable_mechanism()->
          mutable_hmac_parameters()->
          mutable_digest_mechanism()->
          set_mid(SHA1);
  message.mutable_mac_message()->
          mutable_init_message()->
          mutable_mechanism()->
          mutable_hmac_parameters()->
          mutable_key_id()->
          set_id((void const *) key_id.id, sizeof(key_id.id));
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  VhsmMessage message = create_mac_message(VhsmMacMessage::UPDATE, session);
  VhsmResponse response;
  
  message.mutable_mac_message()->
          mutable_update_message()->
          mutable_data_chunk()->
          set_data((void const *)data_chunk, chunk_size);
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_mac_get_size(vhsm_session session, unsigned int * mac_size) {
  VhsmMessage message = create_mac_message(VhsmMacMessage::GET_MAC_SIZE, session);
  VhsmResponse response;
  
  return send_message_unsigned_int_response(message, response, mac_size);
}

vhsm_rv vhsm_tr_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int mac_size) {
  VhsmMessage message = create_mac_message(VhsmMacMessage::END, session);
  VhsmResponse response;
  
  return send_message_raw_data_response(message, response, mac_ptr, mac_size);
}


//
// key management functions
//

static VhsmMessage create_key_management_message(VhsmKeyMgmtMessage_MessageType type, vhsm_session session) {
  VhsmMessage message;
  
  message.mutable_session()->
          set_sid(session.sid);
  
  message.set_message_class(KEY_MGMT);
  message.mutable_key_mgmt_message()->
          set_type(type);
  
  return message;
}

vhsm_rv vhsm_tr_key_mgmt_get_key_ids_count(vhsm_session session, unsigned int * ids_count) {
  VhsmMessage message = create_key_management_message(VhsmKeyMgmtMessage::GET_KEY_IDS_COUNT, session);
  VhsmResponse response;
  
  return send_message_unsigned_int_response(message, response, ids_count);
}

vhsm_rv vhsm_tr_key_mgmt_get_key_ids(vhsm_session session, vhsm_key_id * ids, unsigned int ids_count) {
  VhsmMessage message = create_key_management_message(VhsmKeyMgmtMessage::GET_KEY_IDS, session);
  VhsmResponse response;
  
  return send_message_key_ids_response(message, response, ids, ids_count);
}

vhsm_rv vhsm_tr_key_mgmt_delete_key(vhsm_session session, vhsm_key_id key_id) {
  VhsmMessage message = create_key_management_message(VhsmKeyMgmtMessage::DELETE_KEY, session);
  VhsmResponse response;
  
  message.mutable_key_mgmt_message()->
          mutable_delete_key_message()->
          mutable_key_id()->
          set_id((void const *) key_id.id, sizeof(key_id.id));
  
  return send_message_ok_response(message, response);
}

vhsm_rv vhsm_tr_key_mgmt_import_key(vhsm_session session, vhsm_key key, int purpose, bool force_import, vhsm_key_id *key_id, unsigned int key_length) {
  VhsmMessage message = create_key_management_message(VhsmKeyMgmtMessage::CREATE_KEY, session);
  VhsmResponse response;
  
  message.mutable_key_mgmt_message()->
          mutable_create_key_message()->
          mutable_key_id()->
          set_id((void const *) key.id.id, sizeof(key.id.id));
  if(key.key_data) {
      message.mutable_key_mgmt_message()->
              mutable_create_key_message()->
              mutable_key()->
              set_key((void const *) key.key_data, key.data_size);
  }
  message.mutable_key_mgmt_message()->
          mutable_create_key_message()->
          set_purpose(purpose);
  message.mutable_key_mgmt_message()->
          mutable_create_key_message()->
          set_force_import(force_import);
  message.mutable_key_mgmt_message()->
          mutable_create_key_message()->
          set_key_length(key_length);
  
  return send_message_raw_data_response(message, response, key_id->id, sizeof(key_id->id));
}

vhsm_rv vhsm_tr_key_mgmt_get_key_info(vhsm_session session, vhsm_key_info *keys, unsigned int keys_count, vhsm_key_id key_id) {
    VhsmMessage message = create_key_management_message(VhsmKeyMgmtMessage::GET_KEY_INFO, session);
    VhsmResponse response;

    if(key_id.id[0] != 0) {
        message.mutable_key_mgmt_message()->
                mutable_get_key_info_message()->
                mutable_key_id()->
                set_id((const void*)key_id.id, sizeof(key_id.id));
    }

    return send_message_key_info_response(message, response, keys, keys_count);
}
