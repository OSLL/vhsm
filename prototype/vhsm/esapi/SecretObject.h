#pragma once

#include <utility>

namespace ES {

  class SecretObject {
  private:
    struct SODataHolder {
      std::string my_name;
      size_t my_size;
      void * my_bytes;
      int my_ref_count;
      
      SODataHolder(std::string const & name, void * data, size_t size)
        : my_name(name), my_size(size), my_bytes(data), my_ref_count(1) {
      }
      
      void hold() {
        ++my_ref_count;
      }
      
      void release() {
        if (0 == --my_ref_count) {
          delete this;
        }
      }
      
      ~SODataHolder() {
          delete [] my_bytes;
      }
    };
  public:
    SecretObject(std::string const & name, void * data, size_t size)
      : my_hldr(new SODataHolder(name, data, size)){
    }
    
    SecretObject(SecretObject const & so) {
      my_hldr = so.my_hldr;
      my_hldr->hold();
    }
    
    SecretObject & operator=(SecretObject const & so) {
      my_hldr->release();
      my_hldr = so.my_hldr;
    }
    
    void const * raw_bytes() {
      return my_hldr->my_bytes;
    }
    
    size_t size() {
      return my_hldr->my_size;
    }
    
    std::string const & name() {
      return my_hldr->my_name;
    }
    
    ~SecretObject() {
      my_hldr->release();
    }
    
  private:
    SODataHolder * my_hldr;
  };

}
