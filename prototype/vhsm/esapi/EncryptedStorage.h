#pragma once

#include <string>
#include <vector>

#include "Namespace.h"

namespace ES {

  class EncryptedStorage {
  public:
    typedef std::vector<unsigned char> Key;
  public:
    virtual std::vector<std::string> list_namespaces() const = 0;
    virtual bool namespace_exists(std::string const & ns) const = 0;
    virtual bool namespace_accessible(std::string const & ns, Key const & key) const = 0;
    
    virtual bool create_namespace(std::string const & ns, Key const & key) = 0;
    virtual bool delete_namespace(std::string const & ns, Key const & key) = 0;
    
    virtual Namespace & load_namespace(std::string const & ns, Key const & key) = 0;
    virtual void unload_namespace(Namespace & ns) = 0;
    
    virtual ~EncryptedStorage() {
    }
  protected:
    EncryptedStorage() {
    }
  private:
    EncryptedStorage(EncryptedStorage const &);
    EncryptedStorage & operator=(EncryptedStorage const &);
  };

}
