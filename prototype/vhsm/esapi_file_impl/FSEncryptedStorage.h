#pragma once

#include <EncryptedStorage.h>


namespace ES {

  class FSEncryptedStorage : public EncryptedStorage {
  private:
    static std::string MAGIC_FILE;
  public:
    FSEncryptedStorage(std::string const & root, bool init = false);
    
    virtual std::vector<std::string> list_namespaces() const;
    
    virtual bool namespace_exists(std::string const & ns) const;
    
    virtual bool namespace_accessible(std::string const & ns, Key const & key) const;
    
    virtual bool create_namespace(std::string const & ns, Key const & key);
    
    virtual bool delete_namespace(std::string const & ns, Key const & key);
    
    virtual Namespace & load_namespace(std::string const & ns, Key const & key);
    
    virtual void unload_namespace(Namespace & ns);
    
    virtual ~FSEncryptedStorage();
  private:
    FSEncryptedStorage(EncryptedStorage const &);
    FSEncryptedStorage & operator=(EncryptedStorage const &);
  private:
    std::string my_root;
  };
  
}
