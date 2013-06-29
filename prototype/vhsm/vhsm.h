#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"
#include "VhsmMessageTransport.h"
#include "esapi/Types.h"

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
    std::string name;
    KeyType key;
};

typedef std::map<ClientId, std::set<VhsmSession> > ClientSessionMap;
typedef std::map<SessionId, VhsmUser> UserMap1;

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
    void closeSession(const VhsmSession &s);

private:
    VhsmMessageTransport transport;
    std::map<VhsmMessageClass, VhsmMessageHandler*> messageHandlers;
    int64_t sessionCounter;

    ClientSessionMap clientSessions;

    bool readMessage(VhsmMessage &msg, ClientId &cid) const;
    bool sendResponse(const VhsmResponse &response, const ClientId &cid) const;

    VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);
    void createMessageHandlers();

    SessionId getNextSessionId();
};

#endif // VHSM_H
