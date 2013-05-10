#pragma once

#include "FileTransportBase.h"
#include "FileTransportMessage.h"

class FileTransportReceiver : FileTransportBase {
private:
  static const useconds_t SLEEP_TIME_USEC = 50000; //50ms
public:
  FileTransportReceiver() {
  }
  
  ssize_t get_message_size() {
    ssize_t message_size = -1;
    
    while (!usleep(SLEEP_TIME_USEC)) {
      if (!lock()) {
        continue;
      }
      
      ssize_t fsz = file_size();
      
      if (-1 == fsz) {
        goto cleanup;
      }
      
      //there is an unread message.
      if (0 != fsz) {
        message_size = do_get_message_size();
        goto cleanup;
      }
      
      if (!unlock()) {
        break;
      }
    }
    
    return message_size;
    
    cleanup:
    unlock();
    
    return message_size;
  }
  
  enum ReceiveMessageRetVal {RM_BUFFER_TOO_SMALL, RM_ERROR, RM_OK};
  
  ReceiveMessageRetVal receive_message(void const * buf, size_t * buf_sz_ptr, int * sender_id = (int *)0) {
    ReceiveMessageRetVal status = RM_OK;
    
    while(!usleep(SLEEP_TIME_USEC)) {
      if (!lock()) {
        continue;
      }
      
      ssize_t fsz = file_size();
      
      if (-1 == fsz) {
        status = RM_ERROR;
        goto cleanup;
      }
      
      //there is an unread message.
      if (0 != fsz) {
        status = do_receive_message(buf, buf_sz_ptr, sender_id);
        goto cleanup;
      }
      
      if (!unlock()) {
        break;
      }
    }
    
    return status;
    
    cleanup:
    unlock();
    
    return status;
  }
  
  virtual ~FileTransportReceiver() {
  }
  
private:
  bool read_message(FileTransportMessage * msg_ptr) {
    if (!seek_start()) {
      return false;
    }
    
    return sizeof(FileTransportMessage) == read(msg_ptr, sizeof(FileTransportMessage));
  }
  
  ssize_t do_get_message_size() {
    FileTransportMessage ftm;
    
    if (!read_message(&ftm)) {
      return -1;
    }
    
    return ftm.msg_size;
  }
  
  ReceiveMessageRetVal do_receive_message(void const * buf, size_t * buf_sz_ptr, int * sender_id) {
    FileTransportMessage msg_header;
    
    if (!read_message(&msg_header)) {
      return RM_ERROR;
    }
    
    if (msg_header.msg_size > *buf_sz_ptr) {
      return RM_BUFFER_TOO_SMALL;
    }
    
    if (0 != sender_id) {
      *sender_id = msg_header.sender_id;
    }
    
    *buf_sz_ptr = msg_header.msg_size;
    
    if (*buf_sz_ptr != read(buf, *buf_sz_ptr)) {
      return RM_ERROR;
    }
    
    return RM_OK;
  }
};
