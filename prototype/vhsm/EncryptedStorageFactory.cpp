#include "esapi_file_impl/FSEncryptedStorage.h"

#include "EncryptedStorageFactory.h"

ES::EncryptedStorage * EncryptedStorageFactory::create_storage() {
  return new ES::FSEncryptedStorage("./data/", false);
}
