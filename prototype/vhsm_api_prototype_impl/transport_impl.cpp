#include "vhsm_transport.pb.h"


//
//transport.h implementation
//

#include "transport.h"

//
// common functions
//

static VhsmMessage create_session_message(VhsmSessionMessage_MessageType type) {
  VhsmMessage message;
  
  message.set_message_class(SESSION);
  message.mutable_session_message()->
          set_type(type);
  
  return message;
}

vhsm_rv vhsm_tr_start_session(vhsm_session * session_ptr) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::START);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_end_session(vhsm_session session) {
  VhsmMessage message = create_session_message(VhsmSessionMessage::END);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_login(vhsm_session session, vhsm_credentials credentials) {
  //TODO implement it when authorization mechanisms are introduced
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_logout(vhsm_session session) {
  //TODO implement it when authorization mechanisms are introduced
  return VHSM_RV_OK;
}


//
// digest functions
//

vhsm_rv vhsm_tr_digest_init_sha1(vhsm_session session) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  message.mutable_digest_message()->
          set_type(VhsmDigestMessage::INIT);
  message.mutable_digest_message()->
          mutable_init_message()->
          mutable_mechanism()->
          set_mid(SHA1);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_digest_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  message.mutable_digest_message()->
          set_type(VhsmDigestMessage::UPDATE);
  message.mutable_digest_message()->
          mutable_update_message()->
          mutable_data_chunk()->
          set_data(std::string((char const *)data_chunk, chunk_size));
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_digest_key(vhsm_session session, vhsm_key_id key_id) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  message.mutable_digest_message()->
          set_type(VhsmDigestMessage::UPDATE_KEY);
  message.mutable_digest_message()->
          mutable_update_key_message()->
          mutable_key_id()->
          set_id(std::string((char const *) key_id.id, sizeof(key_id.id) / sizeof(key_id.id[0])));
  
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_digest_get_size(vhsm_session session, unsigned int * mac_size) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  message.mutable_digest_message()->
          set_type(VhsmDigestMessage::GET_DIGEST_SIZE);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_digest_end(vhsm_session session, unsigned char * digest_ptr, unsigned int digest_size) {
  VhsmMessage message;
  
  message.set_message_class(DIGEST);
  message.mutable_digest_message()->
          set_type(VhsmDigestMessage::END);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}


//
// MAC functions
//

vhsm_rv vhsm_tr_mac_init_hmac_sha1(vhsm_session session) {
  VhsmMessage message;
  
  message.set_message_class(MAC);
  message.mutable_mac_message()->
          set_type(VhsmMacMessage::INIT);
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
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_mac_update(vhsm_session session, unsigned char const * data_chunk, unsigned int chunk_size) {
  VhsmMessage message;
  
  message.set_message_class(MAC);
  message.mutable_mac_message()->
          set_type(VhsmMacMessage::UPDATE);
  message.mutable_mac_message()->
          mutable_update_message()->
          mutable_data_chunk()->
          set_data(std::string((char const *)data_chunk, chunk_size));
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_mac_get_size(vhsm_session session, unsigned int * mac_size) {
  VhsmMessage message;
  
  message.set_message_class(MAC);
  message.mutable_mac_message()->
          set_type(VhsmMacMessage::GET_MAC_SIZE);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}

vhsm_rv vhsm_tr_mac_end(vhsm_session session, unsigned char * mac_ptr, unsigned int mac_size) {
  VhsmMessage message;
  
  message.set_message_class(MAC);
  message.mutable_mac_message()->
          set_type(VhsmMacMessage::GET_MAC_SIZE);
  
  //TODO send the message and receive answer.
  
  //TODO replace with appropriate rv
  return VHSM_RV_OK;
}
