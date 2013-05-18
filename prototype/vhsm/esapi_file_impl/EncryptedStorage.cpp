#include <EncryptedStorage.h>

#include "FSESNamespace.h"
#include "FsUtil.h"

namespace ES {
  
  class FSEncryptedStorage : public EncryptedStorage {
  public:
    FSEncryptedStorage(std::string const & root) : my_root(FsUtil::to_dir_name(root)) {
      //TODO implement me;
    }
    
    virtual std::vector<std::string> list_namespaces() const {
      //TODO implement me;
      return std::vector<std::string>();
    }
    
    virtual bool namespace_exists(std::string const & ns) const {
      //TODO implement me;
      return false;
    }
    
    virtual bool namespace_accessible(std::string const & ns, Key const & key) const {
      //TODO implement me;
      return false;
    }
    
    virtual bool create_namespace(std::string const & ns, Key const & key) {
      //TODO implement me;
      return false;
    }
    
    virtual bool delete_namespace(std::string const & ns, Key const & key) {
      //TODO implement me;
      return false;
    }
    
    virtual Namespace & load_namespace(std::string const & ns, Key const & key) {
      //TODO
      return *(new FSESNamespace(ns, key));
    }
    
    virtual void unload_namespace(Namespace & ns) {
      //TODO implement me;
    }
    
    virtual ~FSEncryptedStorage() {
      //TODO implement me;
    }
  private:
    FSEncryptedStorage(EncryptedStorage const &);
    FSEncryptedStorage & operator=(EncryptedStorage const &);
  private:
    std::string my_root;
  };

}
