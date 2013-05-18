#include <EncryptedStorage.h>

#include <stdexcept>
#include <cstdio>

#include "FSESNamespace.h"
#include "FsUtil.h"

namespace ES {
  
  class FSEncryptedStorage : public EncryptedStorage {
  private:
    static std::string MAGIC_FILE;
  public:
    FSEncryptedStorage(std::string const & root, bool init = false) : my_root(root) {
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
    
    virtual std::vector<std::string> list_namespaces() const {
      return FsUtil::list_directories(my_root);
    }
    
    virtual bool namespace_exists(std::string const & ns) const {
      std::string nsroot(my_root);
      nsroot.append(ns);
      
      return FsUtil::directory_exists(FsUtil::to_dir_name(nsroot));
    }
    
    virtual bool namespace_accessible(std::string const & ns, Key const & key) const {
      try {
        FSESNamespace(std::string(my_root).append(ns), key, false);
        return true;
      } catch (std::runtime_error re) {
        return false;
      }
    }
    
    virtual bool create_namespace(std::string const & ns, Key const & key) {
      try {
        FSESNamespace(std::string(my_root).append(ns), key, true);
        return true;
      } catch (std::runtime_error re) {
        return false;
      }
    }
    
    virtual bool delete_namespace(std::string const & ns, Key const & key) {
      //TODO implement me;
      return false;
    }
    
    virtual Namespace & load_namespace(std::string const & ns, Key const & key) {
      return *(new FSESNamespace(std::string(my_root).append(ns), key));
    }
    
    virtual void unload_namespace(Namespace & ns) {
      delete &ns;
    }
    
    virtual ~FSEncryptedStorage() {
    }
  private:
    FSEncryptedStorage(EncryptedStorage const &);
    FSEncryptedStorage & operator=(EncryptedStorage const &);
  private:
    std::string my_root;
  };
  
  std::string FSEncryptedStorage::MAGIC_FILE("__fses_root__");
  
}
