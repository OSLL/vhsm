#ifndef VHSM_H
#define VHSM_H

#include "vhsm_transport.pb.h"

struct ClientId {
    bool operator<(const ClientId &other) const {
        return id < other.id;
    }

    int64_t id;
};

struct VhsmPrivateKey {
    VhsmPrivateKey() : key(0), length(0) {}
    unsigned char *key;
    size_t length;
};

// extracts private key for the given ClientId
VhsmPrivateKey getClientPrivateKey(const std::string &username, const VhsmKeyId &key_id);

VhsmResponse handleMessage(VhsmMessage &m, ClientId &id);

#endif // VHSM_H
