#include <iostream>

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "message.h"

unsigned int const SLEEP_TIME = 1;


int main(int argc, char **argv) {
  if (2 != argc) {
    std::cout << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 0;
  }
  
  int fd = open(argv[1], O_RDWR);
  
  if (-1 == fd) {
    std::cout << "Failed to open file: " << argv[1] << std::endl;
    return 0;
  }
  
  while (!sleep(SLEEP_TIME)) {
    if (-1 == flock(fd, LOCK_EX)) {
      std::cout << "Failed to acquire lock" << std::endl;
      continue;
    }
    
    lseek(fd, 0, SEEK_SET);
    
    char buf[sizeof(Message)] = {};
    ssize_t retval = read(fd, (void *) buf, sizeof(Message));
    
    lseek(fd, 0, SEEK_SET);
    
    if (sizeof(Message) != retval) {
      std::cout << "read(2) failed" << std::endl;
    } else {
      Message * msg = (Message *) buf;
      
      msg->is_read = true;
      std::cout << "read message: " << msg->message << std::endl;
      
      retval = write(fd, (const void *)buf, sizeof(Message));
      if (sizeof(Message) != retval) {
        std::cout << "write(2) failed" << std::endl;
      }
      
      if(-1 == fsync(fd)) {
        std::cout << "fsync(2) failed" << std::endl;
      }
    }
    
    if (-1 == flock(fd, LOCK_UN)) {
      std::cout << "Failed to release lock" << std::endl;
      return 0;
    }
  }
  
  return 0;
}
