#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"
#include "common.h"
#include "VhsmMessageTransport.h"
#include "VhsmStorage.h"
#include <hmac.h>
#include <set>

typedef std::map<ClientId, std::set<SessionId> > ClientSessionMap;
typedef std::map<SessionId, VhsmUser> UserMap;
typedef std::map<std::string, std::set<SessionId> > UserSessionMap;

typedef CryptoPP::HMAC_Base HMAC_CTX;
typedef CryptoPP::HashTransformation Digest_CTX;

typedef std::map<SessionId, HMAC_CTX*> HMACContextMap;
typedef std::map<SessionId, Digest_CTX*> DigestContextMap;

#define VHSM_APP_OK                 0
#define VHSM_APP_STORAGE_ERROR      1
#define VHSM_APP_TRANSPORT_ERROR    2

//------------------------------------------------------------------------------

class VhsmMessageHandler;

class VHSM {
public:
    VHSM(const std::string &storageRoot = "./data");
    ~VHSM();

    int run();

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

    ErrorCode importKey(const SessionId &sid, std::string &keyId, const std::string &keyData, int purpose, size_t length, bool forceImport);
    ErrorCode deleteKey(const SessionId &sid, const std::string &keyId);
    int getKeyIdsCount(const SessionId &sid) const;
    std::vector<std::string> getKeyIds(const SessionId &sid) const;
    std::vector<VhsmKeyInfo> getKeyInfo(const SessionId &sid, const std::string &keyID = "") const;

private:
    VhsmMessageTransport transport;
    VhsmStorage storage;
    std::map<VhsmMessageClass, VhsmMessageHandler*> messageHandlers;
    int64_t sessionCounter;
    bool registered;

    UserMap users;
    UserSessionMap userSessions;
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
