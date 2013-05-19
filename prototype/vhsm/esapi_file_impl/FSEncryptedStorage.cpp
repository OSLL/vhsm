#include <stdexcept>
#include <cstdio>

#include "FSEncryptedStorage.h"
#include "FSESNamespace.h"
#include "FsUtil.h"


namespace ES {
  
  FSEncryptedStorage::FSEncryptedStorage(std::string const & root, bool init) : my_root(root) {
    FsUtil::to_dir_name(my_root);
    
    std::string magic_file(my_root);
    magic_file.append(MAGIC_FILE);
    
    if (!init) {
      if (!FsUtil::file_exists(magic_file)) {
        throw std::runtime_error("Encrypted storage root not initialized.");
      }
    } else {
      if (!FsUtil::create_directory(my_root)) {
        throw std::runtime_error("Failed to create encrypted storage root directory.");
      }
      
      FILE * f = fopen(magic_file.c_str(), "a");
      
      if (0 == f || 0 != fclose(f)) {
        throw std::runtime_error("Failed to initialize encrypted storage.");
      }
    }
  }
  
  std::vector<std::string> FSEncryptedStorage::list_namespaces() const {
    return FsUtil::list_directories(my_root);
  }
  
  bool FSEncryptedStorage::namespace_exists(std::string const & ns) const {
    std::string nsroot(my_root);
    nsroot.append(ns);
    
    return FsUtil::directory_exists(FsUtil::to_dir_name(nsroot));
  }
  
  bool FSEncryptedStorage::namespace_accessible(std::string const & ns, Key const & key) const {
    try {
      FSESNamespace(std::string(my_root).append(ns), key, false);
      return true;
    } catch (std::runtime_error re) {
      return false;
    }
  }
  
  bool FSEncryptedStorage::create_namespace(std::string const & ns, Key const & key) {
    try {
      FSESNamespace(std::string(my_root).append(ns), key, true);
      return true;
    } catch (std::runtime_error re) {
      return false;
    }
  }
  
  bool FSEncryptedStorage::delete_namespace(std::string const & ns, Key const & key) {
    //TODO implement me;
    return false;
  }
  
  Namespace & FSEncryptedStorage::load_namespace(std::string const & ns, Key const & key) {
    return *(new FSESNamespace(std::string(my_root).append(ns), key));
  }
  
  void FSEncryptedStorage::unload_namespace(Namespace & ns) {
    delete &ns;
  }
  
  FSEncryptedStorage::~FSEncryptedStorage() {
  }
  
  std::string FSEncryptedStorage::MAGIC_FILE("__fses_root__");
  
}
