#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"
#include "common.h"
#include "VhsmMessageTransport.h"
#include "VhsmStorage.h"
#include <crypto++/hmac.h>
#include <set>

typedef std::map<ClientId, std::set<SessionId> > ClientSessionMap;
typedef std::map<SessionId, VhsmUser> UserMap;

typedef CryptoPP::HMAC_Base HMAC_CTX;
typedef CryptoPP::HashTransformation Digest_CTX;

typedef std::map<SessionId, HMAC_CTX*> HMACContextMap;
typedef std::map<SessionId, Digest_CTX*> DigestContextMap;

//------------------------------------------------------------------------------

class VHSM;

class VhsmMessageHandler {
    typedef std::map<int, VhsmMessageHandler*> HandlerMap;

public:
    VhsmMessageHandler();
    virtual ~VhsmMessageHandler();

    virtual VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);

private:
    virtual int getMessageType(const VhsmMessage &msg) const = 0;
    virtual bool preprocess(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss, VhsmResponse &r) const;

protected:
    HandlerMap handlers;
};

//------------------------------------------------------------------------------

/*
class VhsmStorage {
public:
    VhsmStorage();
    ~VhsmStorage();

    bool hasUser(const VhsmUser &user) const;
    PKeyType getUserPrivateKey(const VhsmUser &user, const std::string &keyId) const;

    ErrorCode createKey(const VhsmUser &user, const std::string &keyId, const std::string &keyData);
    ErrorCode deleteKey(const VhsmUser &user, const std::string &keyId);
    std::vector<std::string> getKeyIds(const VhsmUser &user) const;

private:
    ES::EncryptedStorage *storage;
};
*/

//------------------------------------------------------------------------------

class VHSM {
public:
    VHSM();
    ~VHSM();

    void run();

    VhsmSession openSession(const ClientId &id);
    bool closeSession(const ClientId &id, const VhsmSession &s);

    bool isLoggedIn(const ClientId &id, const SessionId &sid) const;
    bool loginUser(const std::string &username, const std::string &password, const SessionId &sid);
    bool logoutUser(const SessionId &sid);

    bool isSupportedMacMethod(const VhsmMacMechanismId &mid, const VhsmDigestMechanismId &did) const;
    ErrorCode macInit(const VhsmMacMechanismId &mid, const VhsmDigestMechanismId &did, const SessionId &sid, const std::string &keyId);
    ErrorCode macUpdate(const SessionId &sid, const std::string &data);
    ErrorCode macGetSize(const SessionId &sid, unsigned int *size) const;
    ErrorCode macFinal(const SessionId &sid, std::vector<char> &ds);

    bool isSupportedDigestMethod(const VhsmDigestMechanismId &did) const;
    ErrorCode digestInit(const VhsmDigestMechanismId &did, const SessionId &sid);
    ErrorCode digestUpdate(const SessionId &sid, const std::string &data);
    ErrorCode digestGetSize(const SessionId &sid, unsigned int *size) const;
    ErrorCode digestFinal(const SessionId &sid, std::vector<char> &ds);

    ErrorCode createKey(const SessionId &sid, const std::string &keyId, const std::string &keyData);
    ErrorCode deleteKey(const SessionId &sid, const std::string &keyId);
    std::vector<std::string> getKeyIds(const SessionId &sid) const;
    std::vector<VhsmKeyInfo> getKeyInfo(const SessionId &sid, const std::string &keyID = "") const;

private:
    VhsmMessageTransport transport;
    VhsmStorage storage;
    std::map<VhsmMessageClass, VhsmMessageHandler*> messageHandlers;
    int64_t sessionCounter;

    UserMap users;
    ClientSessionMap clientSessions;
    HMACContextMap clientHmacContexts;
    DigestContextMap clientDigestContexts;

    bool readMessage(VhsmMessage &msg, ClientId &cid) const;
    bool sendResponse(const VhsmResponse &response, const ClientId &cid) const;

    VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);

    void createMessageHandlers();
    SessionId getNextSessionId();
    HMAC_CTX *createHMACCtx(const VhsmDigestMechanismId &did, PKeyType &pkey) const;
    Digest_CTX *createDigestCtx(const VhsmDigestMechanismId &did) const;

};

#endif // VHSM_H
