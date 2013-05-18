#pragma once

#include <string>
#include <vector>

#include "SecretObject.h"

namespace ES {
  
  class Namespace {
  public:
    virtual std::string get_name() const = 0;
    
    virtual std::vector<std::string> list_object_names() const = 0;
    virtual bool contains_object(std::string const & name) const = 0;
    virtual SecretObject load_object(std::string const & name) const = 0;
    
    virtual bool store_object(std::string const & name, void const * data, size_t size);
    virtual bool delete_object(std::string const & name) = 0;
    
    virtual ~Namespace() {
    }
  };
  
}
