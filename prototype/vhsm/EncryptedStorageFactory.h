#pragma once

#include "esapi/EncryptedStorage.h"

class EncryptedStorageFactory {
public:
  ES::EncryptedStorage * create_storage();
};
