#include "esapi_file_impl/FSEncryptedStorage.h"

#include "EncryptedStorageFactory.h"

ES::EncryptedStorage * EncryptedStorageFactory::create_storage(std::string const & root, bool init) {
  return new ES::FSEncryptedStorage(root, init);
}

ES::EncryptedStorage * EncryptedStorageFactory::create_storage(bool init) {
  return create_storage("./data/", init);
}
