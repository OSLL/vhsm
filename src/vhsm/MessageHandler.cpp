#include "MessageHandler.h"
#include <map>
#include <stdexcept>
#include <iostream>

static inline void errorResponse(VhsmResponse &r, ErrorCode ec) {
    r.set_type(VhsmResponse::ERROR);
    r.set_error_code(ec);
}

static inline void okResponse(VhsmResponse &r) {
    r.set_type(VhsmResponse::OK);
}

static inline void makeResponse(VhsmResponse &r, ErrorCode ec) {
    ec == ERR_NO_ERROR ? okResponse(r) : errorResponse(r, ec);
}

static inline VhsmResponse makeResponse(ErrorCode ec) {
    VhsmResponse r;
    ec == ERR_NO_ERROR ? okResponse(r) : errorResponse(r, ec);
    return r;
}

static inline void uintResponse(VhsmResponse &r, unsigned int val) {
    r.set_type(VhsmResponse::UNSIGNED_INT);
    r.set_unsigned_int(val);
}

static inline void rawResponse(VhsmResponse &r, const char *data, unsigned int length) {
    r.set_type(VhsmResponse::RAW_DATA);
    r.mutable_raw_data()->set_data(data, length);
}

//------------------------------------------------------------------------------

VhsmMessageHandler::VhsmMessageHandler() {}

VhsmMessageHandler::~VhsmMessageHandler() {
    for(HandlerMap::iterator i = handlers.begin(); i != handlers.end(); ++i) {
        delete i->second;
    }
}

VhsmResponse VhsmMessageHandler::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    if(!preprocess(vhsm, msg, id, uss, r)) return r;

    HandlerMap::iterator h = handlers.find(getMessageType(msg));
    if(h == handlers.end()) {
        errorResponse(r, ERR_VHSM_ERROR);
        return r;
    }

    return h->second->handle(vhsm, msg, id, uss);
}

bool VhsmMessageHandler::preprocess(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss, VhsmResponse &r) const {
    if(!vhsm.isLoggedIn(id, uss.sid())) {
        errorResponse(r, ERR_NOT_AUTHORIZED);
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------

SessionMessageHandler::SessionMessageHandler() : VhsmMessageHandler() {
    handlers.insert(std::make_pair(VhsmSessionMessage::START, new StartHandler()));
    handlers.insert(std::make_pair(VhsmSessionMessage::END, new EndHandler()));
    handlers.insert(std::make_pair(VhsmSessionMessage::LOGIN, new LoginHandler()));
    handlers.insert(std::make_pair(VhsmSessionMessage::LOGOUT, new LogoutHandler()));
}

VhsmResponse SessionMessageHandler::StartHandler::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    VhsmSession s = vhsm.openSession(id);
    r.set_type(VhsmResponse::SESSION);
    r.mutable_session()->set_sid(s.sid());
    return r;
}

VhsmResponse SessionMessageHandler::EndHandler::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    if(vhsm.closeSession(id, uss)) okResponse(r);
    else errorResponse(r, ERR_BAD_SESSION);
    return r;
}

VhsmResponse SessionMessageHandler::LoginHandler::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    const VhsmSessionMessage &m = msg.session_message();

    if(m.has_login_message()) {
        if(vhsm.loginUser(m.login_message().username(), m.login_message().password(), uss.sid())) okResponse(r);
        else errorResponse(r, ERR_BAD_CREDENTIALS);
    } else errorResponse(r, ERR_BAD_CREDENTIALS);
    return r;
}

VhsmResponse SessionMessageHandler::LogoutHandler::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    vhsm.logoutUser(uss.sid()) ? okResponse(r) : errorResponse(r, ERR_BAD_SESSION);
    return r;
}

//------------------------------------------------------------------------------

MacMessageHandler::MacMessageHandler() : VhsmMessageHandler() {
    handlers.insert(std::make_pair(VhsmMacMessage::INIT, new InitHandler()));
    handlers.insert(std::make_pair(VhsmMacMessage::UPDATE, new UpdateHandler()));
    handlers.insert(std::make_pair(VhsmMacMessage::GET_MAC_SIZE, new GetMacSizeHandler()));
    handlers.insert(std::make_pair(VhsmMacMessage::END, new EndHandler()));
}

VhsmResponse MacMessageHandler::InitHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    const VhsmMacMessage_Init &msg = m.mac_message().init_message();
    const VhsmMacMechanismId &mid = msg.mechanism().mid();
    const VhsmDigestMechanismId &did = msg.mechanism().hmac_parameters().digest_mechanism().mid();

    if(!vhsm.isSupportedMacMethod(mid, did)) {
        errorResponse(r, ERR_BAD_MAC_METHOD);
    } else {
        return makeResponse(vhsm.macInit(mid, did, uss.sid(), msg.mechanism().hmac_parameters().key_id().id().c_str()));
    }

    return r;
}

VhsmResponse MacMessageHandler::UpdateHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    return makeResponse(vhsm.macUpdate(uss.sid(), m.mac_message().update_message().data_chunk().data()));
}

VhsmResponse MacMessageHandler::GetMacSizeHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    unsigned int size = 0;
    ErrorCode res = vhsm.macGetSize(uss.sid(), &size);
    res == ERR_NO_ERROR ? uintResponse(r, size) : errorResponse(r, res);
    return r;
}

VhsmResponse MacMessageHandler::EndHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    std::vector<char> ds;
    ErrorCode res = vhsm.macFinal(uss.sid(), ds);
    res == ERR_NO_ERROR ? rawResponse(r, ds.data(), ds.size()) : errorResponse(r, res);
    return r;
}

//----------------------------------------------------------------------------------------

DigestMessageHandler::DigestMessageHandler() : VhsmMessageHandler() {
    handlers.insert(std::make_pair(VhsmDigestMessage::INIT, new InitHandler()));
    handlers.insert(std::make_pair(VhsmDigestMessage::UPDATE, new UpdateHandler()));
    handlers.insert(std::make_pair(VhsmDigestMessage::UPDATE_KEY, new UpdateKeyHandler()));
    handlers.insert(std::make_pair(VhsmDigestMessage::GET_DIGEST_SIZE, new GetDigestSizeHandler()));
    handlers.insert(std::make_pair(VhsmDigestMessage::END, new EndHandler()));
}

VhsmResponse DigestMessageHandler::InitHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    const VhsmDigestMechanismId &mid = m.digest_message().init_message().mechanism().mid();
    if(vhsm.isSupportedDigestMethod(mid)) makeResponse(r, vhsm.digestInit(mid, uss.sid()));
    else errorResponse(r, ERR_BAD_DIGEST_METHOD);
    return r;
}

VhsmResponse DigestMessageHandler::UpdateHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    return makeResponse(vhsm.digestUpdate(uss.sid(), m.digest_message().update_message().data_chunk().data()));
}

VhsmResponse DigestMessageHandler::UpdateKeyHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    errorResponse(r, ERR_BAD_DIGEST_METHOD);
    return r;
}

VhsmResponse DigestMessageHandler::GetDigestSizeHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    unsigned int size = 0;
    ErrorCode res = vhsm.digestGetSize(uss.sid(), &size);
    res == ERR_NO_ERROR ? uintResponse(r, size) : errorResponse(r, res);
    return r;
}

VhsmResponse DigestMessageHandler::EndHandler::handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    std::vector<char> ds;
    ErrorCode res = vhsm.digestFinal(uss.sid(), ds);
    res == ERR_NO_ERROR ? rawResponse(r, ds.data(), ds.size()) : errorResponse(r, res);
    return r;
}

//----------------------------------------------------------------------------------------

KeyMgmtMessageHandler::KeyMgmtMessageHandler() : VhsmMessageHandler() {
    handlers.insert(std::make_pair(VhsmKeyMgmtMessage::CREATE_KEY, new CreateKey()));
    handlers.insert(std::make_pair(VhsmKeyMgmtMessage::DELETE_KEY, new DeleteKey()));
    handlers.insert(std::make_pair(VhsmKeyMgmtMessage::GET_KEY_IDS, new GetKeyIds()));
    handlers.insert(std::make_pair(VhsmKeyMgmtMessage::GET_KEY_IDS_COUNT, new GetKeyIdsCount()));
    handlers.insert(std::make_pair(VhsmKeyMgmtMessage::GET_KEY_INFO, new GetKeyInfo()));
}

VhsmResponse KeyMgmtMessageHandler::CreateKey::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    const VhsmKeyMgmtMessage_CreateKey &m = msg.key_mgmt_message().create_key_message();
    std::string keyID = m.key_id().id().c_str();
    std::string key = m.has_key() ? m.key().key() : "";
    ErrorCode res = vhsm.importKey(uss.sid(), keyID, key, m.purpose(), m.force_import());
    res == ERR_NO_ERROR ? rawResponse(r, keyID.c_str(), keyID.size()) : errorResponse(r, res);
    return r;
}

VhsmResponse KeyMgmtMessageHandler::DeleteKey::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    return makeResponse(vhsm.deleteKey(uss.sid(), msg.key_mgmt_message().delete_key_message().key_id().id().c_str()));
}


VhsmResponse KeyMgmtMessageHandler::GetKeyIds::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;

    std::vector<std::string> ids = vhsm.getKeyIds(uss.sid());
    r.set_type(VhsmResponse::KEY_ID_LIST);
    for(std::vector<std::string>::iterator i = ids.begin(); i != ids.end(); ++i) {
        r.mutable_key_ids()->add_ids()->set_id(*i);
    }

    return r;
}


VhsmResponse KeyMgmtMessageHandler::GetKeyIdsCount::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    uintResponse(r, vhsm.getKeyIdsCount(uss.sid()));
    return r;
}


VhsmResponse KeyMgmtMessageHandler::GetKeyInfo::handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    const VhsmKeyMgmtMessage_GetKeyInfo &m = msg.key_mgmt_message().get_key_info_message();
    std::string keyID = m.has_key_id() ? m.key_id().id().c_str() : "";
    std::vector<VhsmKeyInfo> kinfo = vhsm.getKeyInfo(uss.sid(), keyID);
    r.set_type(VhsmResponse::KEY_INFO_LIST);

    for(std::vector<VhsmKeyInfo>::iterator i = kinfo.begin(); i != kinfo.end(); ++i) {
        KeyInfo *ki = r.mutable_key_info()->add_keys();
        ki->mutable_id()->set_id(i->keyID);
        ki->set_length(i->length);
        ki->set_purpose(i->purpose);
        ki->set_time(i->importDate);
    }

    return r;
}
