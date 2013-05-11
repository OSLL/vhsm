#include "vhsm.h"
#include <crypto++/hmac.h>
#include <crypto++/sha.h>
#include <map>

typedef CryptoPP::HMAC<CryptoPP::SHA1> HMAC_SHA1_CTX;
typedef CryptoPP::SHA1 SHA1_CTX;

typedef std::map<ClientId, HMAC_SHA1_CTX*> HMACContextMap;
typedef std::map<ClientId, SHA1_CTX*> SHA1ContextMap;
typedef std::map<ClientId, VhsmSession> SessionMap;

static SessionMap clientSessions;
static HMACContextMap clientContexts;
static SHA1ContextMap clientDigests;
static int64_t sessionCounter = 0;

//------------------------------------------------------------------------------

static int64_t getNextSessionId() {
    return sessionCounter++;
}

static bool hasOpenSession(const ClientId &id) {
    return clientSessions.find(id) != clientSessions.end();
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

const char* getClientPrivateKey(const ClientId &id) {
    //some code here for key extraction
    return "secret_key";
}

//------------------------------------------------------------------------------

static VhsmResponse handleSessionMessage(const VhsmSessionMessage &m, const ClientId &id) {
    VhsmResponse r;
    switch(m.type()) {
    case VhsmSessionMessage::START:
        if(clientSessions.find(id) != clientSessions.end()) errorResponse(r, ERR_BAD_SESSION);
        else {
            int64_t sid = getNextSessionId();
            VhsmSession s;
            s.set_sid(sid);
            clientSessions.insert(std::make_pair(id, s));
            r.set_type(VhsmResponse::SESSION);
            r.mutable_session()->set_sid(sid);
        }
        break;
    case VhsmSessionMessage::END:
        if(clientSessions.find(id) == clientSessions.end()) errorResponse(r, ERR_BAD_SESSION);
        else {
            HMACContextMap::iterator hi = clientContexts.find(id);
            if(hi != clientContexts.end()) {
                delete hi->second;
                clientContexts.erase(hi);
            }
            SHA1ContextMap::iterator di = clientDigests.find(id);
            if(di != clientDigests.end()) {
                delete di->second;
                clientDigests.erase(di);
            }

            if(clientSessions.erase(id) != 1) errorResponse(r, ERR_VHSM_ERROR);
            else okResponse(r);
        }
        break;
    default:
        errorResponse(r, ERR_VHSM_ERROR);
    }

    return r;
}

static VhsmResponse handleMacMessage(const VhsmMacMessage &m, const ClientId &id) {
    VhsmResponse r;
    HMACContextMap::iterator i = clientContexts.find(id);

    switch(m.type()) {
    case VhsmMacMessage::INIT: {
        const VhsmMacMessage_Init &msg = m.init_message();
        if(msg.mechanism().mid() != HMAC
                || !msg.mechanism().has_hmac_parameters()
                || !msg.mechanism().hmac_parameters().digest_mechanism().mid() != SHA1) {
            errorResponse(r, ERR_BAD_MAC_METHOD);
        } else {
            const char *pkey = getClientPrivateKey(id);
            if(pkey != 0) {
                HMAC_SHA1_CTX *hctx = new HMAC_SHA1_CTX((const byte*)pkey, strlen(pkey));
                if(!clientContexts.insert(std::make_pair(id, hctx)).second) errorResponse(r, ERR_MAC_INIT);
                else okResponse(r);
            } else errorResponse(r, ERR_KEY_NOT_FOUND);
        }
        break;
    }
    case VhsmMacMessage::UPDATE: {
        const VhsmMacMessage_Update &msg = m.update_message();
        if(i != clientContexts.end()) {
            try {
                i->second->Update((const byte*)msg.data_chunk().data().c_str(), msg.data_chunk().data().length());
                okResponse(r);
            } catch(...) {
                errorResponse(r, ERR_VHSM_ERROR);
                return r;
            }
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

static VhsmResponse handleDigestMessage(const VhsmDigestMessage &m, const ClientId &id) {
    VhsmResponse r;
    SHA1ContextMap::iterator i = clientDigests.find(id);

    switch(m.type()) {
    case VhsmDigestMessage::INIT:
        switch(m.init_message().mechanism().mid()) {
        case SHA1: {
            SHA1_CTX *ctx = new SHA1_CTX();
            if(clientDigests.insert(std::make_pair(id, ctx)).second) okResponse(r);
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

VhsmResponse handleMessage(VhsmMessage &m, ClientId &id) {
    VhsmResponse r;
    switch(m.message_class()) {
    case SESSION:
        return handleSessionMessage(m.session_message(), id);
    case MAC:
        if(hasOpenSession(id)) return handleMacMessage(m.mac_message(), id);
        errorResponse(r, ERR_BAD_SESSION);
        break;
    case DIGEST:
        if(hasOpenSession(id)) return handleDigestMessage(m.digest_message(), id);
        errorResponse(r, ERR_BAD_SESSION);
        break;
    default:
        errorResponse(r, ERR_BAD_ARGUMENTS);
    }
    return r;
}
