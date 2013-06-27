#include "vhsm.h"
#include "EncryptedStorageFactory.h"
#include <crypto++/hmac.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/files.h>
#include <map>
#include <set>
#include <stdexcept>

typedef CryptoPP::HMAC<CryptoPP::SHA1> HMAC_SHA1_CTX;
typedef CryptoPP::SHA1 SHA1_CTX;

typedef ES::Key KeyType;
typedef int64_t SessionId;

typedef std::map<ClientId, std::set<VhsmSession> > ClSsMap;
typedef std::map<SessionId, ClientId> SsClMap;
typedef std::map<SessionId, std::string> UserMap;
typedef std::map<SessionId, HMAC_SHA1_CTX*> HMACContextMap;
typedef std::map<SessionId, SHA1_CTX*> SHA1ContextMap;
typedef std::map<std::string, KeyType> KeyMap;

static ClSsMap clientSessions;
static UserMap clientNames;
static HMACContextMap clientContexts;
static SHA1ContextMap clientDigests;
static KeyMap clientKeys;
static int64_t sessionCounter = 0;

static bool operator<(const VhsmSession &s1, const VhsmSession &s2) {
    return s1.sid() < s2.sid();
}

//------------------------------------------------------------------------------

static SessionId getNextSessionId() {
    return sessionCounter++;
}

static bool hasOpenSession(const ClientId &id) {
    return clientSessions.find(id) != clientSessions.end();
}

static std::string userNameForSession(SessionId sid) {
    UserMap::iterator it = clientNames.find(sid);
    if(it != clientNames.end()) return it->second;
    return std::string();
}

static std::string userNameForSession(const VhsmSession &s) {
    return userNameForSession(s.sid());
}

static KeyType keyForUser(const std::string &u) {
    KeyMap::iterator it = clientKeys.find(u);
    if(it != clientKeys.end()) return it->second;
    return KeyType();
}

static bool hasLoggedIn(const VhsmSession &s) {
    return clientKeys.find(userNameForSession(s)) != clientKeys.end();
}

static bool hasLoggedIn(const std::string &u) {
    return clientKeys.find(u) != clientKeys.end();
}

//------------------------------------------------------------------------------

static inline void errorResponse(VhsmResponse &r, ErrorCode ec) {
    r.set_type(VhsmResponse::ERROR);
    r.set_error_code(ec);
}

static inline void okResponse(VhsmResponse &r) {
    r.set_type(VhsmResponse::OK);
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

static ES::EncryptedStorage * encrypted_storage = 0;

static ES::EncryptedStorage *getStorage() {
    if (0 == encrypted_storage) {
      encrypted_storage = EncryptedStorageFactory().create_storage();
    }
    
    return encrypted_storage;
}

static KeyType convertKey(byte *k, size_t ln) {
    KeyType key(ln);
    for(size_t i = 0; i < ln; ++i) key[i] = k[i];
    return key;
}

//------------------------------------------------------------------------------

bool authClient(const VhsmSessionMessage_Login &m, KeyType &key) {
    CryptoPP::SHA256 keyHashCtx;
    byte keyHash[32];
    keyHashCtx.Update((byte*)m.password().c_str(), m.password().size());
    keyHashCtx.Final(keyHash);
    key = convertKey(keyHash, 32);

    return getStorage()->namespace_accessible(m.username(), key);
}

//------------------------------------------------------------------------------

static VhsmResponse handleSessionMessage(const VhsmSessionMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    switch(m.type()) {
    case VhsmSessionMessage::START: {
        int64_t sid = getNextSessionId();
        VhsmSession s;
        s.set_sid(sid);
        ClSsMap::iterator cs = clientSessions.find(id);
        if(cs == clientSessions.end()) {
            std::set<VhsmSession> ss; ss.insert(s);
            clientSessions.insert(std::make_pair(id, ss));
        } else {
            cs->second.insert(s);
        }
        r.set_type(VhsmResponse::SESSION);
        r.mutable_session()->set_sid(sid);
        break;
    }
    case VhsmSessionMessage::END: {
        ClSsMap::iterator cs = clientSessions.find(id);
        if(cs == clientSessions.end()) errorResponse(r, ERR_BAD_SESSION);
        else {
            HMACContextMap::iterator hi = clientContexts.find(uss.sid());
            if(hi != clientContexts.end()) {
                delete hi->second;
                clientContexts.erase(hi);
            }
            SHA1ContextMap::iterator di = clientDigests.find(uss.sid());
            if(di != clientDigests.end()) {
                delete di->second;
                clientDigests.erase(di);
            }

            KeyMap::iterator ki = clientKeys.find(userNameForSession(uss));
            if(ki != clientKeys.end()) clientKeys.erase(ki);

            UserMap::iterator ui = clientNames.find(uss.sid());
            if(ui != clientNames.end()) clientNames.erase(ui);

            if(cs->second.size() == 1) clientSessions.erase(id);
            else cs->second.erase(uss);
            okResponse(r);
        }
        break;
    }
    case VhsmSessionMessage::LOGIN:
        if(m.has_login_message()) {
            KeyType key;
            if(authClient(m.login_message(), key)) {
                clientKeys.insert(std::make_pair(m.login_message().username(), key));
                clientNames.insert(std::make_pair(uss.sid(), m.login_message().username()));
                okResponse(r);
            } else errorResponse(r, ERR_BAD_CREDENTIALS);
        } else errorResponse(r, ERR_BAD_CREDENTIALS);
        break;
    case VhsmSessionMessage::LOGOUT: {
        KeyMap::iterator it = clientKeys.find(userNameForSession(uss));
        if(it != clientKeys.end()) {
            clientKeys.erase(it);
            UserMap::iterator ut = clientNames.find(uss.sid());
            if(ut != clientNames.end()) {
                clientNames.erase(ut);
                okResponse(r);
            } else errorResponse(r, ERR_VHSM_ERROR);
        } else errorResponse(r, ERR_BAD_CREDENTIALS);
        break;
    }
    default:
        errorResponse(r, ERR_VHSM_ERROR);
    }

    return r;
}

//----------------------------------------------------------------------------------------

static VhsmResponse handleMacMessage(const VhsmMacMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    std::string username = userNameForSession(uss);
    if(username.empty() || !hasLoggedIn(username)) {
        errorResponse(r, ERR_NOT_AUTHORIZED);
        return r;
    }

    HMACContextMap::iterator i = clientContexts.find(uss.sid());
    switch(m.type()) {
    case VhsmMacMessage::INIT: {
        const VhsmMacMessage_Init &msg = m.init_message();
        if(msg.mechanism().mid() != HMAC
                || !msg.mechanism().has_hmac_parameters()
                || msg.mechanism().hmac_parameters().digest_mechanism().mid() != SHA1) {
            errorResponse(r, ERR_BAD_MAC_METHOD);
        } else {
            try {
                ES::Namespace &ns = getStorage()->load_namespace(username, keyForUser(username));
                ES::SecretObject pkey = ns.load_object(msg.mechanism().hmac_parameters().key_id().id());
                HMAC_SHA1_CTX *hctx = new HMAC_SHA1_CTX((byte*)pkey.raw_bytes(), pkey.size());
                if(!clientContexts.insert(std::make_pair(uss.sid(), hctx)).second) errorResponse(r, ERR_MAC_INIT);
                else okResponse(r);
                getStorage()->unload_namespace(ns);
            } catch (std::runtime_error re) {
                errorResponse(r, ERR_KEY_NOT_FOUND);
            }
        }
        break;
    }
    case VhsmMacMessage::UPDATE: {
        const VhsmMacMessage_Update &msg = m.update_message();
        if(i != clientContexts.end()) {
//            try {
                i->second->Update((const byte*)msg.data_chunk().data().c_str(), msg.data_chunk().data().length());
                okResponse(r);
//            } catch(...) {
//                errorResponse(r, ERR_VHSM_ERROR);
//                return r;
//            }
        } else errorResponse(r, ERR_MAC_NOT_INITIALIZED);
        break;
    }
    case VhsmMacMessage::GET_MAC_SIZE: {
        if(i != clientContexts.end()) uintResponse(r, i->second->DigestSize());
        else errorResponse(r, ERR_MAC_NOT_INITIALIZED);
        break;
    }
    case VhsmMacMessage::END: {
        if(i != clientContexts.end()) {
            HMAC_SHA1_CTX *ctx = i->second;
            unsigned int len = ctx->DigestSize();
            byte *dgst = new byte[len];
            try {
                ctx->Final(dgst);
                rawResponse(r, (const char*)dgst, len);
                // !!! WARNING !!!
                delete ctx;
                clientContexts.erase(i);
            } catch(...) {
                // memory leak?
                errorResponse(r, ERR_VHSM_ERROR);
                return r;
            }
        } else errorResponse(r, ERR_MAC_NOT_INITIALIZED);
        break;
    }
    default:
        errorResponse(r, ERR_BAD_MAC_METHOD);
    }
    return r;
}

//----------------------------------------------------------------------------------------

static VhsmResponse handleDigestMessage(const VhsmDigestMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;
    if(!hasLoggedIn(uss)) {
        errorResponse(r, ERR_NOT_AUTHORIZED);
        return r;
    }

    SHA1ContextMap::iterator i = clientDigests.find(uss.sid());
    switch(m.type()) {
    case VhsmDigestMessage::INIT:
        switch(m.init_message().mechanism().mid()) {
        case SHA1: {
            SHA1_CTX *ctx = new SHA1_CTX();
            if(clientDigests.insert(std::make_pair(uss.sid(), ctx)).second) okResponse(r);
            else errorResponse(r, ERR_DIGEST_INIT);
            break;
        }
        default:
            errorResponse(r, ERR_BAD_DIGEST_METHOD);
        }
        break;
    case VhsmDigestMessage::UPDATE:
        if(i != clientDigests.end()) {
            try {
                i->second->Update((const byte*)m.update_message().data_chunk().data().c_str(), m.update_message().data_chunk().data().length());
                okResponse(r);
            } catch(...) {
                errorResponse(r, ERR_VHSM_ERROR);
                return r;
            }
        } else errorResponse(r, ERR_DIGEST_NOT_INITIALIZED);
        break;
    case VhsmDigestMessage::UPDATE_KEY:             //currently unused method;
        errorResponse(r, ERR_BAD_DIGEST_METHOD);
        break;
    case VhsmDigestMessage::GET_DIGEST_SIZE:
        if(i != clientDigests.end()) uintResponse(r, i->second->DigestSize());
        else errorResponse(r, ERR_DIGEST_NOT_INITIALIZED);
        break;
    case VhsmDigestMessage::END:
        if(i != clientDigests.end()) {
            SHA1_CTX *ctx = i->second;
            unsigned int len = ctx->DigestSize();
            byte *dgst = new byte[len];
            try {
                ctx->Final(dgst);
                rawResponse(r, (const char*)dgst, len);
                // !!! WARNING !!!
                delete ctx;
                clientDigests.erase(i);
            } catch(...) {
                errorResponse(r, ERR_VHSM_ERROR);
                return r;
            }
        } else errorResponse(r, ERR_DIGEST_NOT_INITIALIZED);
        break;
    default:
        errorResponse(r, ERR_BAD_DIGEST_METHOD);
    }
    return r;
}

//----------------------------------------------------------------------------------------

static VhsmResponse handleKeyMgmtMessage(const VhsmKeyMgmtMessage &m, const ClientId &id, const VhsmSession &uss) {
    VhsmResponse r;

    std::string username = userNameForSession(uss);
    if(username.empty() || !hasLoggedIn(username)) {
        errorResponse(r, ERR_NOT_AUTHORIZED);
        return r;
    }
    KeyType userkey = keyForUser(username);

//    try{
        ES::Namespace &uns = getStorage()->load_namespace(username, userkey);
        switch(m.type()) {
        case VhsmKeyMgmtMessage::CREATE_KEY:
            if(uns.store_object(m.create_key_message().key_id().id(),
                             m.create_key_message().key().key().data(),
                             m.create_key_message().key().key().size())) {
                okResponse(r);
            } else errorResponse(r, ERR_KEY_ID_OCCUPIED);
            break;
        case VhsmKeyMgmtMessage::DELETE_KEY:
            if(uns.delete_object(m.delete_key_message().key_id().id())) okResponse(r);
            else errorResponse(r, ERR_KEY_NOT_FOUND);
            break;
        case VhsmKeyMgmtMessage::GET_KEY_IDS: {
            std::vector<std::string> ids = uns.list_object_names();
            r.set_type(VhsmResponse::KEY_ID_LIST);
            for(std::vector<std::string>::iterator i = ids.begin(); i != ids.end(); ++i) {
                r.mutable_key_ids()->add_ids()->set_id(*i);
            }
            break;
        }
        case VhsmKeyMgmtMessage::GET_KEY_IDS_COUNT:
            uintResponse(r, uns.list_object_names().size());
            break;
        }
        getStorage()->unload_namespace(uns);
//    } catch (...) {
//        errorResponse(r, ERR_VHSM_ERROR);
//    }

    return r;
}

//----------------------------------------------------------------------------------------

VhsmResponse VHSM::handleMessage(VhsmMessage &m, ClientId &id) {
    VhsmResponse r;
    switch(m.message_class()) {
    case SESSION:
        return handleSessionMessage(m.session_message(), id, m.session());
    case MAC:
        if(hasOpenSession(id)) return handleMacMessage(m.mac_message(), id, m.session());
        errorResponse(r, ERR_BAD_SESSION);
        break;
    case DIGEST:
        if(hasOpenSession(id)) return handleDigestMessage(m.digest_message(), id, m.session());
        errorResponse(r, ERR_BAD_SESSION);
        break;
    case KEY_MGMT:
        if(hasOpenSession(id)) return handleKeyMgmtMessage(m.key_mgmt_message(), id, m.session());
        errorResponse(r, ERR_BAD_SESSION);
        break;
    default:
        errorResponse(r, ERR_BAD_ARGUMENTS);
    }
    return r;
}
