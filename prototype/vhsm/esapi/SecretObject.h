#pragma once

#include <utility>

namespace ES {

  class SecretObject {
  public:
    SecretObject(std::string const & name, void * data, size_t size) :
      my_name(name), my_bytes(data), my_size(size), ref_count(0) {
      //TODO implement me
    }
    
    //TODO add copy constructor, assignment operator.
    
    void const * raw_bytes() {
      return my_bytes;
    }
    
    size_t size() {
      return my_size;
    }
    
    std::string const & name() {
      return my_name;
    }
    
  private:
    std::string my_name;
    size_t my_size;
    void * my_bytes;
    int * ref_count;
  };

}
