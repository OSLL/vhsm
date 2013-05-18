#pragma once

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


namespace ES {

  class FsUtil {
  public:
    static bool directory_exists(std::string const & path) {
      struct stat s;
      
      return read_stat(path, &s) ? S_ISDIR(s.st_mode) : false;
    }
    
    static bool file_exists(std::string const & path) {
      struct stat s;
      
      return read_stat(path, &s) ? S_ISREG(s.st_mode) : false;
    }
    
    static std::string to_dir_name(std::string const & path) {
      return to_dir_name(std::string(path));
    }
    
    static std::string & to_dir_name(std::string & path) {
      if ('/' != path[path.size() - 1]) {
        path.push_back('/');
      }
      
      return path;
    }
    
    static std::vector<std::string> list_directories(std::string const & path) {
      //TODO implement me;
      return std::vector<std::string>();
    }
    
    static std::vector<std::string> list_files(std::string const & path) {
      //TODO implement me;
      return std::vector<std::string>();
    }
    
  private:
    static bool read_stat(std::string const & path, struct stat * s) {
      return 0 == stat(path.c_str(), s);
    }
  private:
    FsUtil();
    FsUtil(FsUtil const &);
    FsUtil & operator=(FsUtil const &);
  };

}
