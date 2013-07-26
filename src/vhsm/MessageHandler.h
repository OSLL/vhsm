#ifndef MESSAGEHANDLER_H
#define MESSAGEHANDLER_H

#include "vhsm.h"
#include <map>

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
    SessionMessageHandler();

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.session_message().type();
    }

    bool preprocess(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss, VhsmResponse &r) const {
        return true;
    }

    class StartHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class LoginHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class LogoutHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };
};

//------------------------------------------------------------------------------

class MacMessageHandler : public VhsmMessageHandler {
public:
    MacMessageHandler();

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.mac_message().type();
    }

    class InitHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class UpdateHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class GetMacSizeHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };
};

//----------------------------------------------------------------------------------------

class DigestMessageHandler : public VhsmMessageHandler {
public:
    DigestMessageHandler();

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.digest_message().type();
    }

    class InitHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class UpdateHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class UpdateKeyHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class GetDigestSizeHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };

    class EndHandler : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &m, const ClientId &id, const VhsmSession &uss);
    };
};

//----------------------------------------------------------------------------------------

class KeyMgmtMessageHandler : public VhsmMessageHandler {
public:
    KeyMgmtMessageHandler();

private:
    int getMessageType(const VhsmMessage &msg) const {
        return (int)msg.key_mgmt_message().type();
    }

    class CreateKey : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class DeleteKey : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class GetKeyIds : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class GetKeyIdsCount : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };

    class GetKeyInfo : public VhsmLocalMessageHandler {
    public:
        VhsmResponse handle(VHSM &vhsm, const VhsmMessage &msg, const ClientId &id, const VhsmSession &uss);
    };
};

#endif // MESSAGEHANDLER_H
