#include <iostream>

#include "vhsm.h"

#include <FileTransportSender.h>
#include <FileTransportReceiver.h>

static useconds_t const SLEEP_TIME_USEC = 50000; //50ms

//TODO these paths should be configured dynamically
static char const * VHSM_IO_IN = "io_vhsm_from_host";
static char const * VHSM_IO_OUT = "io_vhsm_to_host";

static bool read_message(FileTransportReceiver & receiver, VhsmMessage & msg, ClientId & cid) {
  ssize_t msg_size = 0;
  int sender_id = 0;
  char * buf = 0;
  bool result = false;
  
  msg_size = receiver.get_message_size();
  
  if (-1 == msg_size) {
    std::cerr << "failed to read message size" << std::endl;
    goto cleanup;
  }
  
  buf = new char[msg_size];
  if (FileTransportReceiver::RM_OK != receiver.receive_message(buf, (size_t *)&msg_size, &sender_id)) {
    std::cerr << "error receiving message" << std ::endl;
    goto cleanup;
  }
  
  cid.id = sender_id;
  
  result = msg.ParseFromArray(buf, msg_size);
  if (!result) {
    std::cerr << "ill-formed message received" << std::endl;
  }
  
  cleanup:
  if (0 != buf) {
    delete [] buf;
  }
  
  return result;
}

static bool send_response(FileTransportSender & sender, VhsmResponse const & response, int sender_id) {
  size_t serialized_sz = response.ByteSize();
  char * buf = new char[serialized_sz];
  bool result = false;
  
  if (!response.SerializeToArray(buf, serialized_sz)) {
    goto cleanup;
  }
  
  result = sender.send_message(buf, serialized_sz, sender_id);
  
  cleanup:
  if (0 != buf) {
    delete [] buf;
  }
  
  return result;
}

static void start_vhsm(FileTransportReceiver & receiver, FileTransportSender & sender) {
  while(!usleep(SLEEP_TIME_USEC)) {
    VhsmMessage msg;
    ClientId cid;
    
    if (!read_message(receiver, msg, cid)) {
      std::cerr << "failed to read message" << std::endl;
      return;
    }
    
    if (!send_response(sender, handleMessage(msg, cid), (int) cid.id)) {
      std::cerr << "failed to send response" << std::endl;
      return;
    }
  }
}


int main(int argc, char ** argv) {
  FileTransportReceiver receiver;
  FileTransportSender sender;
  
  if (!receiver.open(VHSM_IO_IN) || !sender.open(VHSM_IO_OUT)) {
    std::cerr << "failed to open one or more file for transport" << std::endl;
    return 1;
  }
  
  start_vhsm(receiver, sender);
  
  return !receiver.close() || !sender.close();
}
