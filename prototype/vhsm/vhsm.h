#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"
#include "VhsmMessageTransport.h"

struct ClientId {
    bool operator<(const ClientId &other) const {
        return id < other.id;
    }

    int64_t id;
    uint32_t pid;
    uint32_t veid;
};

class VHSM {
public:
    VHSM();
    ~VHSM();

    void run();

private:
    VhsmMessageTransport transport;

    bool read_message(VhsmMessage &msg, ClientId &cid) const;
    bool send_response(const VhsmResponse &response, const ClientId &cid) const;

    VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);
};

#endif // VHSM_H
