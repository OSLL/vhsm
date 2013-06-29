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

static bool checkLogin(const VhsmSession &uss, const ClientId &id) {
    if(!hasOpenSession(id)) return false;
    return hasLoggedIn(uss);
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
    if(!checkLogin(uss, id)) {
        errorResponse(r, ERR_NOT_AUTHORIZED);
        return false;
    }
    return true;
}

//------------------------------------------------------------------------------

class VhsmLocalMessageHandler : public VhsmMessageHandler {
public:
    VhsmLocalMessageHandler() {}

    virtual VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) = 0;

private:
    int getMessageType(const VhsmMessage &msg) const {
        return 0;
    }

    bool preprocess(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss, VhsmResponse &r) const {
        return true;
    }
};

//------------------------------------------------------------------------------

class SessionMessageHandler : public VhsmMessageHandler {
public:
    SessionMessageHandler() : VhsmMessageHandler() {
        handlers.insert(std::make_pair(VhsmSessionMessage::START, new StartHandler()));
        handlers.insert(std::make_pair(VhsmSessionMessage::END, new EndHandler()));
        handlers.insert(std::make_pair(VhsmSessionMessage::LOGIN, new LoginHandler()));
        handlers.insert(std::make_pair(VhsmSessionMessage::LOGOUT, new LogoutHandler()));
    }

private:
//    VhsmSessionMessage::MessageType getMessageType(const VhsmMessage &msg) const {
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.session_message().type();
    }

    bool preprocess(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss, VhsmResponse &r) const {
        return true;
    }

    class StartHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            VhsmSession s = vhsm.openSession(id);

//            int64_t sid = getNextSessionId();
//            VhsmSession s;
//            s.set_sid(sid);
//            ClSsMap::iterator cs = clientSessions.find(id);
//            if(cs == clientSessions.end()) {
//                std::set<VhsmSession> ss; ss.insert(s);
//                clientSessions.insert(std::make_pair(id, ss));
//            } else {
//                cs->second.insert(s);
//            }
            r.set_type(VhsmResponse::SESSION);
            r.mutable_session()->set_sid(s.sid());

            return r;
        }
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;

            ClSsMap::iterator cs = clientSessions.find(id);
            if(cs == clientSessions.end()) {
                errorResponse(r, ERR_BAD_SESSION);
                return r;
            }

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
            return r;
        }
    };

    class LoginHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            const VhsmSessionMessage &m = msg.session_message();

            if(m.has_login_message()) {
                KeyType key;
                if(authClient(m.login_message(), key)) {
                    clientKeys.insert(std::make_pair(m.login_message().username(), key));
                    clientNames.insert(std::make_pair(uss.sid(), m.login_message().username()));
                    okResponse(r);
                } else errorResponse(r, ERR_BAD_CREDENTIALS);
            } else errorResponse(r, ERR_BAD_CREDENTIALS);
            return r;
        }
    };

    class LogoutHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;

            KeyMap::iterator it = clientKeys.find(userNameForSession(uss));
            if(it != clientKeys.end()) {
                clientKeys.erase(it);
                UserMap::iterator ut = clientNames.find(uss.sid());
                if(ut != clientNames.end()) {
                    clientNames.erase(ut);
                    okResponse(r);
                } else errorResponse(r, ERR_VHSM_ERROR);
            } else errorResponse(r, ERR_BAD_CREDENTIALS);
            return r;
        }
    };
};

//------------------------------------------------------------------------------

class MacMessageHandler : public VhsmMessageHandler {
public:
    MacMessageHandler() : VhsmMessageHandler() {
        handlers.insert(std::make_pair(VhsmMacMessage::INIT, new InitHandler()));
        handlers.insert(std::make_pair(VhsmMacMessage::UPDATE, new UpdateHandler()));
        handlers.insert(std::make_pair(VhsmMacMessage::GET_MAC_SIZE, new GetMacSizeHandler()));
        handlers.insert(std::make_pair(VhsmMacMessage::END, new EndHandler()));
    }

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.mac_message().type();
    }

    class InitHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            const VhsmMacMessage_Init &msg = m.mac_message().init_message();
            if(msg.mechanism().mid() != HMAC
                    || !msg.mechanism().has_hmac_parameters()
                    || msg.mechanism().hmac_parameters().digest_mechanism().mid() != SHA1) {
                errorResponse(r, ERR_BAD_MAC_METHOD);
            } else {
                try {
                    std::string username = userNameForSession(uss);
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

            return r;
        }
    };

    class UpdateHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            const VhsmMacMessage_Update &msg = m.mac_message().update_message();
            HMACContextMap::iterator i = clientContexts.find(uss.sid());
            if(i != clientContexts.end()) {
                //            try {
                i->second->Update((const byte*)msg.data_chunk().data().c_str(), msg.data_chunk().data().length());
                okResponse(r);
                //            } catch(...) {
                //                errorResponse(r, ERR_VHSM_ERROR);
                //                return r;
                //            }
            } else errorResponse(r, ERR_MAC_NOT_INITIALIZED);
            return r;
        }
    };

    class GetMacSizeHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            HMACContextMap::iterator i = clientContexts.find(uss.sid());
            if(i != clientContexts.end()) uintResponse(r, i->second->DigestSize());
            else errorResponse(r, ERR_MAC_NOT_INITIALIZED);
            return r;
        }
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            HMACContextMap::iterator i = clientContexts.find(uss.sid());
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

            return r;
        }
    };
};

//----------------------------------------------------------------------------------------

class DigestMessageHandler : public VhsmMessageHandler {
public:
    DigestMessageHandler() : VhsmMessageHandler() {
        handlers.insert(std::make_pair(VhsmDigestMessage::INIT, new InitHandler()));
        handlers.insert(std::make_pair(VhsmDigestMessage::UPDATE, new UpdateHandler()));
        handlers.insert(std::make_pair(VhsmDigestMessage::UPDATE_KEY, new UpdateKeyHandler()));
        handlers.insert(std::make_pair(VhsmDigestMessage::GET_DIGEST_SIZE, new GetDigestSizeHandler()));
        handlers.insert(std::make_pair(VhsmDigestMessage::END, new EndHandler()));
    }

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.digest_message().type();
    }

    class InitHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            switch(m.digest_message().init_message().mechanism().mid()) {
            case SHA1: {
                SHA1_CTX *ctx = new SHA1_CTX();
                if(clientDigests.insert(std::make_pair(uss.sid(), ctx)).second) okResponse(r);
                else errorResponse(r, ERR_DIGEST_INIT);
                break;
            }
            default:
                errorResponse(r, ERR_BAD_DIGEST_METHOD);
            }
            return r;
        }
    };

    class UpdateHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            SHA1ContextMap::iterator i = clientDigests.find(uss.sid());
            if(i != clientDigests.end()) {
                try {
                    i->second->Update((const byte*)m.digest_message().update_message().data_chunk().data().c_str(),
                                      m.digest_message().update_message().data_chunk().data().length());
                    okResponse(r);
                } catch(...) {
                    errorResponse(r, ERR_VHSM_ERROR);
                    return r;
                }
            } else errorResponse(r, ERR_DIGEST_NOT_INITIALIZED);
            return r;
        }
    };

    class UpdateKeyHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            errorResponse(r, ERR_BAD_DIGEST_METHOD);
            return r;
        }
    };

    class GetDigestSizeHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            SHA1ContextMap::iterator i = clientDigests.find(uss.sid());
            if(i != clientDigests.end()) uintResponse(r, i->second->DigestSize());
            else errorResponse(r, ERR_DIGEST_NOT_INITIALIZED);
            return r;
        }
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            SHA1ContextMap::iterator i = clientDigests.find(uss.sid());
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
            return r;
        }
    };
};

//----------------------------------------------------------------------------------------

class KeyMgmtMessageHandler : public VhsmMessageHandler {
public:
    KeyMgmtMessageHandler() : VhsmMessageHandler() {
        handlers.insert(std::make_pair(VhsmKeyMgmtMessage::CREATE_KEY, new CreateKey()));
        handlers.insert(std::make_pair(VhsmKeyMgmtMessage::DELETE_KEY, new DeleteKey()));
        handlers.insert(std::make_pair(VhsmKeyMgmtMessage::GET_KEY_IDS, new GetKeyIds()));
        handlers.insert(std::make_pair(VhsmKeyMgmtMessage::GET_KEY_IDS_COUNT, new GetKeyIdsCount()));
    }

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.key_mgmt_message().type();
    }

    static ES::Namespace &getNamespaceForSession(const VhsmSession &uss) {
        std::string username = userNameForSession(uss);
        KeyType userkey = keyForUser(username);
        return getStorage()->load_namespace(username, userkey);
    }

    class CreateKey : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            ES::Namespace &uns = getNamespaceForSession(uss);
            const VhsmKeyMgmtMessage & m = msg.key_mgmt_message();
            if(uns.store_object(m.create_key_message().key_id().id(),
                             m.create_key_message().key().key().data(),
                             m.create_key_message().key().key().size())) {
                okResponse(r);
            } else errorResponse(r, ERR_KEY_ID_OCCUPIED);
            getStorage()->unload_namespace(uns);
            return r;
        }
    };

    class DeleteKey : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            ES::Namespace &uns = getNamespaceForSession(uss);
            if(uns.delete_object(msg.key_mgmt_message().delete_key_message().key_id().id())) okResponse(r);
            else errorResponse(r, ERR_KEY_NOT_FOUND);
            getStorage()->unload_namespace(uns);
            return r;
        }
    };

    class GetKeyIds : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            ES::Namespace &uns = getNamespaceForSession(uss);

            std::vector<std::string> ids = uns.list_object_names();
            r.set_type(VhsmResponse::KEY_ID_LIST);
            for(std::vector<std::string>::iterator i = ids.begin(); i != ids.end(); ++i) {
                r.mutable_key_ids()->add_ids()->set_id(*i);
            }
            getStorage()->unload_namespace(uns);
            return r;
        }
    };

    class GetKeyIdsCount : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss) {
            VhsmResponse r;
            ES::Namespace &uns = getNamespaceForSession(uss);
            uintResponse(r, uns.list_object_names().size());
            getStorage()->unload_namespace(uns);
            return r;
        }
    };
};

//----------------------------------------------------------------------------------------

void VHSM::createMessageHandlers() {
    messageHandlers.insert(std::make_pair(SESSION, new SessionMessageHandler()));
    messageHandlers.insert(std::make_pair(MAC, new MacMessageHandler()));
    messageHandlers.insert(std::make_pair(DIGEST, new DigestMessageHandler()));
    messageHandlers.insert(std::make_pair(KEY_MGMT, new KeyMgmtMessageHandler()));
}

VhsmResponse VHSM::handleMessage(VhsmMessage &m, ClientId &id) {
    std::map<VhsmMessageClass, VhsmMessageHandler*>::iterator h = messageHandlers.find(m.message_class());
    if(h == messageHandlers.end()) {
        VhsmResponse r;
        errorResponse(r, ERR_BAD_ARGUMENTS);
        return r;
    }
    return h->second->handle(*this, m, id, m.session());
}
