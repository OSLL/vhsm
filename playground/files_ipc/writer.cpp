#include <iostream>
#include <string>
#include <sstream>
#include <algorithm>

#include <sys/file.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "message.h"

unsigned int const SLEEP_TIME = 1;

void write_message(int fd, Message * msg) {
  ssize_t retval = write(fd, (const void *)msg, sizeof(Message));
  
  if (sizeof(Message) != retval) {
    std::cout << "write(2) failed" << std::endl;
  }
  
  if(-1 == fsync(fd)) {
    std::cout << "fsync(2) failed" << std::endl;
  }
}

void update_message(Message * msg, int msg_id) {
  std::stringstream ss;
  
  ss << "message#" << msg_id++;
  char const * new_msg = ss.str().c_str();
  
  msg->is_read = false;
  std::copy(new_msg, new_msg + sizeof(msg->message), msg->message);
}

int main(int argc, char **argv) {
  if (2 != argc) {
    std::cout << "Usage: " << argv[0] << " <filename>" << std::endl;
    return 0;
  }
  
  int fd = open(argv[1], O_RDWR);
  
  if (!fd) {
    std::cout << "Failed to open file: " << argv[1] << std::endl;
    return 0;
  }
  
  int msg_id = 0;
  
  while (!sleep(SLEEP_TIME)) {
    if (-1 == flock(fd, LOCK_EX)) {
      std::cout << "Failed to acquire lock" << std::endl;
      continue;
    }
    
    lseek(fd, 0, SEEK_SET);
    
    char buf[sizeof(Message)] = {};
    ssize_t retval = read(fd, (void *) buf, sizeof(Message));
    
    lseek(fd, 0, SEEK_SET);
    
    if (sizeof(Message) == retval) {
      Message * msg = (Message *) buf;
      
      if (msg->is_read) {
        update_message(msg, msg_id++);
        write_message(fd, msg);
      }
    } else if (0 == retval) {
      Message msg;
      
      update_message(&msg, msg_id++);
      write_message(fd, &msg);
    } else {
      std::cout << "read(2) failed" << std::endl;
    }
    
    if (-1 == flock(fd, LOCK_UN)) {
      std::cout << "Failed to release lock" << std::endl;
      return 0;
    }
  }
  
  return 0;
}
