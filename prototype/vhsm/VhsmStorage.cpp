#include "vhsm.h"
#include "EncryptedStorageFactory.h"

VhsmStorage::VhsmStorage() : storage(0) {
    storage = EncryptedStorageFactory().create_storage();
}

VhsmStorage::~VhsmStorage() {
    delete storage;
}

bool VhsmStorage::hasUser(const VhsmUser &user) const {
    return storage->namespace_accessible(user.name, user.key);
}

PKeyType VhsmStorage::getUserPrivateKey(const VhsmUser &user, const std::string &keyId) const {
    ES::Namespace &ns = storage->load_namespace(user.name, user.key);
    ES::SecretObject pkey = ns.load_object(keyId);
    storage->unload_namespace(ns);
    return pkey;
}

ErrorCode VhsmStorage::createKey(const VhsmUser &user, const std::string &keyId, const std::string &keyData) {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    ErrorCode res = uns.store_object(keyId, keyData.data(), keyData.size()) ? ERR_NO_ERROR : ERR_KEY_ID_OCCUPIED;
    storage->unload_namespace(uns);
    return res;
}

ErrorCode VhsmStorage::deleteKey(const VhsmUser &user, const std::string &keyId) {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    ErrorCode res = uns.delete_object(keyId) ? ERR_NO_ERROR : ERR_KEY_NOT_FOUND;
    storage->unload_namespace(uns);
    return res;
}

std::vector<std::string> VhsmStorage::getKeyIds(const VhsmUser &user) const {
    ES::Namespace &uns = storage->load_namespace(user.name, user.key);
    std::vector<std::string> ids = uns.list_object_names();
    storage->unload_namespace(uns);
    return ids;
}
