#ifndef COMMON_H
#define COMMON_H

#include "vhsm_transport.pb.h"

#include <string>
#include <stdint.h>
#include <time.h>

typedef int64_t SessionId;
typedef std::string KeyType;
typedef std::string PKeyType;

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

struct VhsmKeyInfo {
    std::string keyID;
    int purpose;
    size_t length;
    time_t importDate;
};

#endif // COMMON_H
