#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"
#include "VhsmMessageTransport.h"
#include "EncryptedStorageFactory.h"
#include <crypto++/hmac.h>

#include <set>

typedef int64_t SessionId;
typedef ES::Key KeyType;

struct ClientId {
    bool operator<(const ClientId &other) const {
        if(veid != other.veid) return veid < other.veid;
        return pid < other.pid;
    }

    uint32_t pid;
    uint32_t veid;
};

struct VhsmUser {
    VhsmUser(const std::string &n, const KeyType &k) : name(n), key(k) {}

    std::string name;
    KeyType key;
};

typedef std::map<ClientId, std::set<SessionId> > ClientSessionMap;
typedef std::map<SessionId, VhsmUser> UserMap1;

typedef CryptoPP::HMAC_Base HMAC_CTX;
typedef CryptoPP::HashTransformation* Digest_CTX;

typedef std::map<SessionId, HMAC_CTX*> HMACContextMap1;
typedef std::map<SessionId, Digest_CTX*> DigestContextMap;

static const ErrorCode ERR_NO_ERROR = static_cast<ErrorCode>((int)ErrorCode_MIN - 1);

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

private:
    VhsmMessageTransport transport;
    std::map<VhsmMessageClass, VhsmMessageHandler*> messageHandlers;
    int64_t sessionCounter;

    UserMap1 users;
    ClientSessionMap clientSessions;
    HMACContextMap1 clientHmacContexts;
    DigestContextMap clientDigestContexts;

    bool readMessage(VhsmMessage &msg, ClientId &cid) const;
    bool sendResponse(const VhsmResponse &response, const ClientId &cid) const;

    VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);
    void createMessageHandlers();

    SessionId getNextSessionId();

    HMAC_CTX *createHMAC(const VhsmDigestMechanismId &did, ES::SecretObject &pkey) const;
};

#endif // VHSM_H
