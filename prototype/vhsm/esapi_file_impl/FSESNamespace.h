#pragma once

#include <Namespace.h>
#include <EncryptedStorage.h>

namespace ES {
  
  class FSESNamespace : public Namespace {
  public:
    FSESNamespace(std::string const & nsroot, Key const & key) {
      //TODO implement me;
    }
    
    virtual std::string const & get_name() const {
      //TODO implement me;
      return "not implemented";
    }
    
    virtual std::vector<std::string> list_object_names() const {
      //TODO implement me;
      return std::vector<std::string>();
    }
    
    virtual bool contains_object(std::string const & name) const {
      //TODO implement me;
      return false;
    }
    
    virtual SecretObject load_object(std::string const & name) const {
      //TODO implement me;
      return SecretObject("", (void *)0, 0);
    }
    
    virtual bool store_object(std::string const & name, void const * data, size_t size) {
      //TODO implement me;
      return false;
    }
    
    virtual bool delete_object(std::string const & name) {
      //TODO implement me;
      return false;
    }
    
    virtual ~FSESNamespace() {
      //TODO implement me;
    }
  };
  
}
