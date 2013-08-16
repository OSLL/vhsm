
#include <iostream>
#include <stdexcept>
#include <set>
#include <sha.h>

#include "vhsm.h"
#include "MessageHandlerTest.h"
#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include "MessageHandler.h"


//------------------------------------------------------------------------------

VHSM::VHSM(const std::string &storageRoot) : storage(storageRoot), sessionCounter(0) {
    createMessageHandlers();
}

VHSM::~VHSM() {
    for(std::map<VhsmMessageClass, VhsmMessageHandler*>::iterator i = messageHandlers.begin(); i != messageHandlers.end(); ++i) {
        delete i->second;
    }

}

//------------------------------------------------------------------------------

int VHSM::run() {
    VhsmMessage msg;
    ClientId cid;

    while(true) {
        if(!readMessage(msg, cid)) continue;

        if(!sendResponse(handleMessage(msg, cid), cid)) {
            std::cerr << "Unable to send response to veid: " << cid.veid << " pid: " << cid.pid << std::endl;
        }
    }

    return 0;
}

//------------------------------------------------------------------------------

SessionId VHSM::getNextSessionId() {
    return sessionCounter++;
}

VhsmSession VHSM::openSession(const ClientId &id) {
    SessionId sid = getNextSessionId();

    VhsmSession s;
    s.set_sid(sid);
    ClientSessionMap::iterator cs = clientSessions.find(id);
    if(cs == clientSessions.end()) {
        std::set<SessionId> ss; ss.insert(sid);
        clientSessions.insert(std::make_pair(id, ss));
    } else {
        cs->second.insert(sid);
    }

    return s;
}

bool VHSM::closeSession(const ClientId &id, const VhsmSession &s) {
    ClientSessionMap::iterator cs = clientSessions.find(id);
    if(cs == clientSessions.end()) return false;

    HMACContextMap::iterator hi = clientHmacContexts.find(s.sid());
    if(hi != clientHmacContexts.end()) {
        delete hi->second;
        clientHmacContexts.erase(hi);
    }

    DigestContextMap::iterator di = clientDigestContexts.find(s.sid());
    if(di != clientDigestContexts.end()) {
        delete di->second;
        clientDigestContexts.erase(di);
    }

    if(cs->second.size() == 1) clientSessions.erase(id);
    else cs->second.erase(s.sid());

    UserMap::iterator ui = users.find(s.sid());
    if(ui != users.end()) users.erase(ui);

    return true;
}

//------------------------------------------------------------------------------


bool VHSM::isLoggedIn(const ClientId &id, const SessionId &sid) const {
    ClientSessionMap::const_iterator s = clientSessions.find(id);
    if(s == clientSessions.end()) return false;
    if(s->second.find(sid) == s->second.end()) return false;
    return users.find(sid) != users.end();
}

bool VHSM::loginUser(const std::string &username, const std::string &password, const SessionId &sid) {
    if (username == "user" && password == "password") {
        VhsmUser user(username, password);
        users.insert(std::make_pair(sid, user));
        return true;
    }

    return false;
}

bool VHSM::logoutUser(const SessionId &sid) {
    UserMap::iterator it = users.find(sid);
    if(it == users.end()) return false;

    users.erase(it);

    return true;
}

//------------------------------------------------------------------------------

HMAC_CTX *VHSM::createHMACCtx(const VhsmDigestMechanismId &did, PKeyType &pkey) const {
    if(did != SHA1) return NULL;
    return new CryptoPP::HMAC<CryptoPP::SHA1>((byte*)pkey.data(), pkey.size());
}

bool VHSM::isSupportedMacMethod(const VhsmMacMechanismId &mid, const VhsmDigestMechanismId &did) const {
    if(mid == HMAC && did == SHA1) return true;
    return false;
}

ErrorCode VHSM::macInit(const VhsmMacMechanismId &mid, const VhsmDigestMechanismId &did, const SessionId &sid, const std::string &keyId) {
    UserMap::iterator u = users.find(sid);
    if(u == users.end()) return ERR_NOT_AUTHORIZED;

    PKeyType pkey = "asdf";
    ErrorCode res = ERR_NO_ERROR;

    HMAC_CTX *hctx = createHMACCtx(did, pkey);

    if(!hctx) res = ERR_BAD_MAC_METHOD;
    else res = clientHmacContexts.insert(std::make_pair(sid, hctx)).second ? ERR_NO_ERROR : ERR_MAC_INIT;
    return res;
}

ErrorCode VHSM::macUpdate(const SessionId &sid, const std::string &data) {
    HMACContextMap::iterator i = clientHmacContexts.find(sid);
    if(i == clientHmacContexts.end()) return ERR_MAC_NOT_INITIALIZED;
    i->second->Update((const byte*)data.c_str(), data.length());
    return ERR_NO_ERROR;
}

ErrorCode VHSM::macGetSize(const SessionId &sid, unsigned int *size) const {
    HMACContextMap::const_iterator i = clientHmacContexts.find(sid);
    if(i == clientHmacContexts.end()) return ERR_MAC_NOT_INITIALIZED;
    *size = i->second->DigestSize();
    return ERR_NO_ERROR;
}

ErrorCode VHSM::macFinal(const SessionId &sid, std::vector<char> &ds) {
    HMACContextMap::iterator i = clientHmacContexts.find(sid);
    if(i == clientHmacContexts.end()) return ERR_MAC_NOT_INITIALIZED;

    HMAC_CTX *ctx = i->second;
    ds.resize(ctx->DigestSize());
    try {
        ctx->Final(reinterpret_cast<byte*>(ds.data()));
        // !!! WARNING !!!
        delete ctx;
        clientHmacContexts.erase(i);
    } catch(...) {
        // memory leak?
        return ERR_VHSM_ERROR;
    }

    return ERR_NO_ERROR;
}

//------------------------------------------------------------------------------

Digest_CTX *VHSM::createDigestCtx(const VhsmDigestMechanismId &did) const {
    switch(did) {
    case SHA1: return new CryptoPP::SHA1();
    default: return NULL;
    }
}

bool VHSM::isSupportedDigestMethod(const VhsmDigestMechanismId &did) const {
    if(did == SHA1) return true;
    return false;
}

ErrorCode VHSM::digestInit(const VhsmDigestMechanismId &did, const SessionId &sid) {
    Digest_CTX *ctx = createDigestCtx(did);
    if(clientDigestContexts.insert(std::make_pair(sid, ctx)).second) return ERR_NO_ERROR;
    return ERR_DIGEST_INIT;
}

ErrorCode VHSM::digestUpdate(const SessionId &sid, const std::string &data) {
    DigestContextMap::iterator i = clientDigestContexts.find(sid);
    if(i == clientDigestContexts.end()) return ERR_DIGEST_NOT_INITIALIZED;
    try {
        i->second->Update((const byte*)data.c_str(), data.length());
        return ERR_NO_ERROR;
    } catch(...) {
        return ERR_VHSM_ERROR;
    }
}

ErrorCode VHSM::digestGetSize(const SessionId &sid, unsigned int *size) const {
    DigestContextMap::const_iterator i = clientDigestContexts.find(sid);
    if(i == clientDigestContexts.end()) return ERR_DIGEST_NOT_INITIALIZED;
    *size = i->second->DigestSize();
    return ERR_NO_ERROR;
}

ErrorCode VHSM::digestFinal(const SessionId &sid, std::vector<char> &ds) {
    DigestContextMap::iterator i = clientDigestContexts.find(sid);
    if(i == clientDigestContexts.end()) return ERR_DIGEST_NOT_INITIALIZED;
    Digest_CTX *ctx = i->second;
    ds.resize(ctx->DigestSize());
    try {
        ctx->Final(reinterpret_cast<byte*>(ds.data()));
        // !!! WARNING !!!
        delete ctx;
        clientDigestContexts.erase(i);
        return ERR_NO_ERROR;
    } catch(...) {
        return ERR_VHSM_ERROR;
    }
}

//------------------------------------------------------------------------------

ErrorCode VHSM::importKey(const SessionId &sid, std::string &keyId, const std::string &keyData, int purpose, size_t length, bool forceImport) {
    static std::set<std::string> keyIds;
    UserMap::iterator i = users.find(sid);
    if(i == users.end()) return ERR_NOT_AUTHORIZED;
    std::pair<std::set<std::string>::iterator,bool> ret = keyIds.insert(keyId);
    if (!ret.second) {
        return ERR_KEY_ID_OCCUPIED;
    }
    return ERR_NO_ERROR;;
}

ErrorCode VHSM::deleteKey(const SessionId &sid, const std::string &keyId) {
    UserMap::iterator i = users.find(sid);
    if(i == users.end()) return ERR_NOT_AUTHORIZED;
    return ERR_NO_ERROR;
}

int VHSM::getKeyIdsCount(const SessionId &sid) const {
    return 1;
}

std::vector<std::string> VHSM::getKeyIds(const SessionId &sid) const {
    std::vector<std::string> ids;
    ids.push_back("asdf");
    return ids;
}

std::vector<VhsmKeyInfo> VHSM::getKeyInfo(const SessionId &sid, const std::string &keyID) const {
    std::vector<VhsmKeyInfo> kinfo;
    UserMap::const_iterator i = users.find(sid);
    if(i != users.end()) {
        VhsmKeyInfo ki = {"asdf", 0, 4, time(NULL)};
        kinfo.push_back(ki);
    }

    return kinfo;
}

//------------------------------------------------------------------------------

bool VHSM::readMessage(VhsmMessage &msg, ClientId &cid) const {
    return false;
}

bool VHSM::sendResponse(const VhsmResponse &response, const ClientId &cid) const {
    return false;
}
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
        r.set_type(VhsmResponse::ERROR);
        r.set_error_code(ERR_BAD_ARGUMENTS);
        return r;
    }
    return h->second->handle(*this, m, id, m.session());
}
