#pragma once

#include <string>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>

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
      std::vector<std::string> names;
      
      file_names(path, names, DT_DIR);
      
      return names;
    }
    
    static std::vector<std::string> list_files(std::string const & path) {
      std::vector<std::string> names;
      
      file_names(path, names, DT_REG);
      
      return names;
    }
    
    static bool create_directory(std::string const & path) {
      return 0 == mkdir(path.c_str(), 0660);
    }
    
    static std::string get_basename(std::string const & path) {
      char * cpath = new char[path.size() + 1];
      
      std::string bname(basename(cpath));
      
      delete [] cpath;
      
      return bname;
    }
    
    static bool write_file(std::string const & path, void const * bytes, size_t length) {
      int fd = open(path.c_str(), O_WRONLY);
      
      if (-1 == fd) {
        return false;
      }
      
      ssize_t bytes_written = write(fd, bytes, length);
      
      return 0 == close(fd) && length == bytes_written;
    }
    
    static bool read_file(std::string const & path, char ** bytes, size_t * length) {
      int fd = open(path.c_str(), O_RDONLY);
      
      if (-1 == fd) {
        return false;
      }
      
      *length = get_file_size(fd);
      
      *bytes = new char[*length];
      
      ssize_t bytes_read = read(fd, *bytes, *length);
      
      if (bytes_read != *length) {
        delete [] (*bytes);
      }
      
      return 0 == close(fd) && bytes_read == *length;
    }
    
  private:
    static size_t get_file_size(int fd) {
      off_t old_pos = lseek(fd, 0, SEEK_CUR);
      off_t size = lseek(fd, 0, SEEK_END);
      
      lseek(fd, old_pos, SEEK_SET);
      
      return size;
    }
    
    static void file_names(std::string const & path, std::vector<std::string> & names, unsigned char file_type) {
      DIR *dir = opendir(path.c_str());
      struct dirent *de = 0;
      
      if (0 == dir) {
        return;
      }
      
      while (0 != (de = readdir(dir))) {
        if (file_type == de->d_type) {
          names.push_back(std::string(de->d_name));
        }
      }
      
      closedir(dir);
    }
    
    static bool read_stat(std::string const & path, struct stat * s) {
      return 0 == stat(path.c_str(), s);
    }
  private:
    FsUtil();
    FsUtil(FsUtil const &);
    FsUtil & operator=(FsUtil const &);
  };

}
