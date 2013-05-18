#include <stdexcept>
#include <algorithm>

#include "FsUtil.h"
#include "ESCypher.h"

#include "FSESNamespace.h"

namespace ES {
  
  FSESNamespace::FSESNamespace(std::string const & nsroot, Key const & key, bool init)
    : my_root(nsroot), my_key(key) {
    FsUtil::to_dir_name(my_root);
    my_name = FsUtil::get_basename(my_root);
    
    if (!init) {
    verify_ns_structure();
    } else {
    create_ns_structure();
    }
  }
  
  std::string const & FSESNamespace::get_name() const {
    return my_name;
  }
  
  std::vector<std::string> FSESNamespace::list_object_names() const {
    //TODO use name mapping
    return FsUtil::list_files(my_root);
  }
  
  bool FSESNamespace::contains_object(std::string const & name) const {
    //TODO use name mapping
    return FsUtil::file_exists(std::string(my_root).append(name));
  }
  
  SecretObject FSESNamespace::load_object(std::string const & name) const {
    char * data = 0;
    size_t size = 0;
    
    //TODO use name mapping
    if (!read_and_decrypt(std::string(my_root).append(name), &data, &size)) {
      throw std::runtime_error("Failed to read and decrypt object.");
    }
    //TODO use name mapping
    return SecretObject(std::string(my_root).append(name), (void *) data, size);
  }
  
  bool FSESNamespace::store_object(std::string const & name, void const * data, size_t size) {
    //TODO use name mapping
    return encrypt_and_write(std::string(my_root).append(name), (char const *) data, size);
  }
  
  bool FSESNamespace::delete_object(std::string const & name) {
    //TODO use name mapping
    return FsUtil::remove_file(std::string(my_root).append(name));
  }
  
  FSESNamespace::~FSESNamespace() {
  }
  
  void FSESNamespace::verify_ns_structure() const {
    if (!FsUtil::directory_exists(std::string(my_root).append(NS_DIR))
     || !FsUtil::file_exists(check_file_path())) {
      throw std::runtime_error("Invalid namespace structure.");
    }
    if (!check_data_matches()) {
      throw std::runtime_error("Invalid key specified.");
    }
  }
    
  bool FSESNamespace::check_data_matches() const {
    char *data = 0;
    size_t size = 0;
    
    if (!read_and_decrypt(check_file_path(), &data, &size)) {
      return false;
    }
    
    bool result = size == NS_CHECK_DATA.size() && std::equal(data, data + size, NS_CHECK_DATA.begin());
    
    delete [] data;
    
    return result;
  }
    
  void FSESNamespace::create_ns_structure() {
    if (!FsUtil::create_directory(my_root) ||
      !FsUtil::create_directory(std::string(my_root).append(NS_DIR)) || 
      !encrypt_and_write(check_file_path(), NS_CHECK_DATA.c_str(), NS_CHECK_DATA.size())) {
      throw std::runtime_error("Failed to create namespace structure.");
    }
  }
    
  bool FSESNamespace::encrypt_and_write(std::string const & file, char const * data, size_t size) {
    char * encrypted = 0;
    size_t encrypted_size = 0;
    
    if (!Cypher::encrypt(data, size, my_key, &encrypted, &encrypted_size)) {
      return false;
    }
    
    bool is_written = FsUtil::write_file(file, encrypted, encrypted_size);
    
    delete [] encrypted;
    
    return is_written;
  }
    
  bool FSESNamespace::read_and_decrypt(std::string const & file, char ** data, size_t * size) const {
    char *bytes = 0;
    size_t bytes_size = 0;
    
    if (!FsUtil::read_file(file, &bytes, &bytes_size)) {
      return false;
    }
    
    bool result = Cypher::decrypt(bytes, bytes_size, my_key, data, size);
    
    delete [] bytes;
    
    return result;
  }
  
  std::string FSESNamespace::check_file_path() const {
    return std::string(my_root).append(NS_DIR).append(NS_CHECK_FILE);
  }
  
  
  std::string FSESNamespace::NS_DIR("__fses_ns__/");
  std::string FSESNamespace::NS_CHECK_FILE("__fses_ns_cf__");
  std::string FSESNamespace::NS_CHECK_DATA("THIS TEXT IS STORED ENCRYPTED IN A CHECK FILE");
}
