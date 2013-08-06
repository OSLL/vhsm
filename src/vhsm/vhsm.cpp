#include <iostream>
#include <stdexcept>
#include <crypto++/sha.h>

#include "vhsm.h"
#include "MessageHandler.h"

//------------------------------------------------------------------------------

VHSM::VHSM(const std::string &storageRoot) : registered(false), storage(storageRoot), sessionCounter(0) {
    registered = transport.send_data(NULL, 0, VHSM_REGISTER);
    createMessageHandlers();
}

VHSM::~VHSM() {
    for(std::map<VhsmMessageClass, VhsmMessageHandler*>::iterator i = messageHandlers.begin(); i != messageHandlers.end(); ++i) {
        delete i->second;
    }
    transport.send_data(NULL, 0, VHSM_UNREGISTER);
}

//------------------------------------------------------------------------------

int VHSM::run() {
    VhsmMessage msg;
    ClientId cid;

    if(!transport.is_open() || !registered) return VHSM_APP_TRANSPORT_ERROR;
    if(!storage.isOpen()) return VHSM_APP_STORAGE_ERROR;

    while(true) {
        if(!readMessage(msg, cid)) {
            VhsmResponse response;
            response.set_type(VhsmResponse::ERROR);
            response.set_error_code(ERR_VHSM_ERROR);
            sendResponse(response, cid);
            continue;
        }

        if(!sendResponse(handleMessage(msg, cid), cid)) {
            std::cerr << "Unable to send response to veid: " << cid.veid << " pid: " << cid.pid << std::endl;
        }
    }

    return VHSM_APP_OK;
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
        if(!cs->second.insert(sid).second) std::cerr << "Unable to add sid " << sid << " for client " << id.veid << ":" << id.pid << std::endl;
    }

    return s;
}

bool VHSM::closeSession(const ClientId &id, const VhsmSession &s) {
    ClientSessionMap::iterator cs = clientSessions.find(id);
    if(cs == clientSessions.end()) return false;
    std::set<SessionId>::iterator ss = cs->second.find(s.sid());
    if(ss == cs->second.end()) return false;

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
    VhsmUser user(username, password);

    if(storage.loginUser(user)) {
        return users.insert(std::make_pair(sid, user)).second;
    }

    return false;
}

bool VHSM::logoutUser(const SessionId &sid) {
    UserMap::iterator it = users.find(sid);
    if(it == users.end()) return false;

    storage.logoutUser(it->second);

    users.erase(it);

    //need to close all open contexts

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

    PKeyType pkey;
    ErrorCode res = storage.getUserPrivateKey(u->second, keyId, pkey);
    if(res != ERR_NO_ERROR) return res;

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
    if(!ctx) return ERR_BAD_DIGEST_METHOD;
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
    UserMap::iterator i = users.find(sid);
    if(i == users.end()) return ERR_NOT_AUTHORIZED;
    return storage.importKey(i->second, keyData, keyId, purpose, length, forceImport);
}

ErrorCode VHSM::deleteKey(const SessionId &sid, const std::string &keyId) {
    UserMap::iterator i = users.find(sid);
    if(i == users.end()) return ERR_NOT_AUTHORIZED;
    return storage.deleteKey(i->second, keyId);
}

int VHSM::getKeyIdsCount(const SessionId &sid) const {
    int count = -1;
    UserMap::const_iterator i = users.find(sid);
    if(i != users.end()) count = storage.getKeyIdsCount(i->second);
    return count;
}

std::vector<std::string> VHSM::getKeyIds(const SessionId &sid) const {
    std::vector<std::string> ids;
    UserMap::const_iterator i = users.find(sid);
    if(i != users.end()) ids = storage.getKeyIds(i->second);
    return ids;
}

std::vector<VhsmKeyInfo> VHSM::getKeyInfo(const SessionId &sid, const std::string &keyID) const {
    std::vector<VhsmKeyInfo> kinfo;
    UserMap::const_iterator i = users.find(sid);
    if(i != users.end()) kinfo = storage.getKeyInfo(i->second, keyID);
    return kinfo;
}

//------------------------------------------------------------------------------

bool VHSM::readMessage(VhsmMessage &msg, ClientId &cid) const {
    char buf[MAX_MSG_SIZE];
    size_t buf_size = MAX_MSG_SIZE;

    if(!transport.receive_data(buf, &buf_size)) {
        std::cerr << "unable to read data from socket" << std::endl;
        return false;
    }

    vmsghdr *msgh = (vmsghdr*)buf;
    if(msgh->type != VHSM_REQUEST) {
        std::cerr << "wrong message type" << std::endl;
        return false;
    }

    cid.pid = msgh->pid;
    cid.veid = msgh->veid;

    char *msg_data = (char*)(buf + sizeof(vmsghdr));
    bool res = msg.ParseFromArray(msg_data, buf_size - sizeof(vmsghdr));
    if (!res) std::cerr << "ill-formed message received" << std::endl;
    return res;
}

bool VHSM::sendResponse(const VhsmResponse &response, const ClientId &cid) const {
    size_t buf_size = response.ByteSize();
    char *buf = new char[buf_size];

    bool res = false;
    if (response.SerializeToArray(buf, buf_size)) {
        res = transport.send_data(buf, buf_size, VHSM_RESPONSE, cid.pid, cid.veid);
    }

    if (buf) delete[] buf;
    return res;
}

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
