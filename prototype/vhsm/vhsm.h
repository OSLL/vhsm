#ifndef VHSM_H
#define VHSM_H

struct ClientId {
    bool operator<(const ClientId &other) const {
        return id < other.id;
    }

    unsigned long long id;
};


// extracts private key for the given ClientId
const char* getClientPrivateKey(const ClientId &id);

#endif // VHSM_H
