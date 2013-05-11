#pragma once

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

class FileTransportBase {
public:
  FileTransportBase() : my_fd(-1) {
  }
  
  bool open(char const * fname) {
    return -1 != (my_fd = ::open(fname, O_RDWR));
  }
  
  bool close() {
    if (!is_opened()) {
      return true;
    }
    
    int retval = ::close(my_fd);
    
    if (0 == retval) {
      my_fd = -1;
    }
    
    return 0 == retval;
  }
  
  virtual ~FileTransportBase() {
    close();
  }
  
  bool is_opened() {
    return -1 != my_fd;
  }
  
protected:
  bool lock() {
    return is_opened() && -1 != flock(my_fd, LOCK_EX);
  }
  
  bool unlock() {
    return !is_opened() || -1 != flock(my_fd, LOCK_UN);
  }
  
  bool seek_start() {
    return -1 != lseek(my_fd, 0, SEEK_SET);
  }
  
  bool wipe() {
    if (!seek_start()) {
      return false;
    }
    
    return -1 != ftruncate(my_fd, 0);
  }
  
  ssize_t read(void * buf, size_t count) {
    if (!is_opened()) {
      return -1;
    }
    return ::read(my_fd, buf, count);
  }
  
  ssize_t write(void const * buf, size_t count) {
    if (!is_opened()) {
      return -1;
    }
    
    return ::write(my_fd, buf, count);
  }
  
  ssize_t file_size() {
    if (!is_opened()) {
      return -1;
    }
    
    off_t old_pos = ::lseek(my_fd, 0, SEEK_CUR);
    off_t size = ::lseek(my_fd, 0, SEEK_END);
    ::lseek(my_fd, old_pos, SEEK_SET);
    
    return size;
  }
  
  void sync() {
    ::sync();
  }
  
private:
  FileTransportBase(FileTransportBase const &);
  FileTransportBase & operator=(FileTransportBase const &);
private:
  int my_fd;
};
