#pragma once

#include "esapi/EncryptedStorage.h"

class EncryptedStorageFactory {
public:
  ES::EncryptedStorage * create_storage(std::string const & root, bool init = false);
  ES::EncryptedStorage * create_storage(bool init = false);
};
