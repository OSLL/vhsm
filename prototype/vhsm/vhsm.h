#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"

struct ClientId {
    bool operator<(const ClientId &other) const {
        return id < other.id;
    }

    int64_t id;
};

VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);

#endif // VHSM_H
