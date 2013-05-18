#pragma once

#include <Namespace.h>
#include <EncryptedStorage.h>

namespace ES {
  
  class FSESNamespace : public Namespace {
  private:
    static std::string NS_DIR;
    static std::string NS_CHECK_FILE;
    static std::string NS_CHECK_DATA;
  public:
    FSESNamespace(std::string const & nsroot, Key const & key, bool init = false);
    
    virtual std::string const & get_name() const;
    
    virtual std::vector<std::string> list_object_names() const;
    
    virtual bool contains_object(std::string const & name) const;
    
    virtual SecretObject load_object(std::string const & name) const;
    
    virtual bool store_object(std::string const & name, void const * data, size_t size);
    
    virtual bool delete_object(std::string const & name);
    
    virtual ~FSESNamespace();
    
  private:
    void verify_ns_structure() const;
    
    bool check_data_matches() const;
    
    void create_ns_structure();
    
    bool encrypt_and_write(std::string const & file, char const * data, size_t size);
    
    bool read_and_decrypt(std::string const & file, char ** data, size_t * size) const;
    
    std::string check_file_path() const;
  
  private:
    FSESNamespace(FSESNamespace const &);
    FSESNamespace & operator=(FSESNamespace const &);
  private:
    std::string my_root;
    std::string my_name;
    Key my_key;
  };
}
