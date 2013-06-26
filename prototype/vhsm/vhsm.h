#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"

struct ClientId {
    bool operator<(const ClientId &other) const {
        return id < other.id;
    }

    int64_t id;
    uint32_t pid;
    uint32_t veid;
};

VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);

#endif // VHSM_H
