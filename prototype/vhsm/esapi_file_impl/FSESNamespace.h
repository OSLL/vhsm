#pragma once

#include <Namespace.h>
#include <EncryptedStorage.h>

#include "FsUtil.h"

namespace ES {
  
  class FSESNamespace : public Namespace {
  private:
    static std::string NS_DIR;
    static std::string NS_CHECK_FILE;
    static std::string NS_CHECK_DATA;
  public:
    FSESNamespace(std::string const & nsroot, Key const & key, bool init = false) 
      : my_root(nsroot), my_key(key) {
      FsUtil::to_dir_name(my_root);
      my_name = FsUtil::get_basename(my_root);
      
      if (!init) {
        verify_ns_structure();
      } else {
        create_ns_structure();
      }
    }
    
    virtual std::string const & get_name() const {
      return my_name;
    }
    
    virtual std::vector<std::string> list_object_names() const {
      //TODO use name mapping
      return FsUtil::list_files(my_root);
    }
    
    virtual bool contains_object(std::string const & name) const {
      //TODO use name mapping
      return FsUtil::file_exists(std::string(my_root).append(name));
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
      //TODO use name mapping
      return 0 == remove(std::string(my_root).append(name).c_str());
    }
    
    virtual ~FSESNamespace() {
    }
    
    private:
      void verify_ns_structure() {
        if (!FsUtil::directory_exists(std::string(my_root).append(NS_DIR))
         || !FsUtil::file_exists(std::string(my_root).append(NS_DIR).append(NS_CHECK_FILE))) {
          throw std::runtime_error("Invalid namespace structure.");
        }
        if (!check_data_matches()) {
          throw std::runtime_error("Invalid key specified.");
        }
      }
      
      bool check_data_matches() {
        //TODO make sure check data matches with NS_CHECK_DATA
        return false;
      }
      
      void create_ns_structure() {
        if (!FsUtil::create_directory(my_root) ||
            !FsUtil::create_directory(std::string(my_root).append(NS_DIR)) || 
            !encrypt_and_write_check_data()) {
          throw std::runtime_error("Failed to create namespace structure.");
        }
      }
      
      bool encrypt_and_write_check_data() {
        //TODO implement me;
        return false;
      }
    private:
      FSESNamespace(FSESNamespace const &);
      FSESNamespace & operator=(FSESNamespace const &);
    private:
      std::string my_root;
      std::string my_name;
      Key my_key;
  };
  
  std::string FSESNamespace::NS_DIR("__fses_ns__/");
  std::string FSESNamespace::NS_CHECK_FILE("__fses_ns_cf__");
  std::string FSESNamespace::NS_CHECK_DATA("THIS TEXT IS STORED ENCRYPTED IN A CHECK FILE");
}
