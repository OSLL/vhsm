#pragma once

#include "FileTransportBase.h"
#include "FileTransportMessage.h"

class FileTransportSender : public FileTransportBase {
private:
  static const useconds_t SLEEP_TIME_USEC = 50000; //50ms
public:
  FileTransportSender() {
  }
  
  bool send_message(void const * data, size_t size, int sender_id = 0) {
    bool message_sent = false;
    
    while (!usleep(SLEEP_TIME_USEC)) {
      if (!lock()) {
        continue;
      }
      
      ssize_t fsz = file_size();
      
      if (-1 == fsz) {
        goto cleanup;
      }
      
      //we can only write message if previous one was read by someone.
      if (0 == fsz) {
        message_sent = -1 != do_send(data, size, sender_id);
        goto cleanup;
      }
      
      if (!unlock()) {
        break;
      }
    }
    
    return message_sent;
    
    cleanup: unlock();
    
    return message_sent;
  }
  
  virtual ~FileTransportSender() {
  }
  
private:
  ssize_t do_send(void const * data, size_t size, int sender_id) {
    ssize_t retval = 0;
    ssize_t bytes_written = 0;
    FileTransportMessage msg;
    
    msg.sender_id = sender_id;
    msg.msg_size = size;
    
    if (!wipe()) {
      return -1;
    }
    
    retval = write((void const *)&msg, sizeof(msg));
    if (-1 == retval) {
      wipe();
      return -1;
    }
    
    bytes_written += retval;
    
    retval = write(data, size);
    if (-1 == retval) {
      wipe();
      return -1;
    }
    
    bytes_written += retval;
    
    sync();
    
    return bytes_written;
  }
};
