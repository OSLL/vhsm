#include <iostream>

#include <FileTransportReceiver.h>
#include <FileTransportSender.h>

static useconds_t const SLEEP_TIME_USEC = 50000; //50ms

//TODO these paths should be configured dynamically
static char const * VHSM_IO_IN = "io_vhsm_to_host";
static char const * VHSM_IO_OUT = "io_vhsm_from_host";

static char const * CONTAINER_IO_IN = "1/send_data";
static char const * CONTAINER_IO_OUT = "1/recv_data";


static bool forward_message(FileTransportReceiver & from,
                            FileTransportSender & to,
                            bool alter_sid = false,
                            int sender_id = 0) {
  bool result = false;
  ssize_t msg_sz = from.get_message_size();
  if (-1 == msg_sz) {
    return false;
  }
  
  char * buf = new char[msg_sz];
  
  switch (alter_sid ? from.receive_message(buf, (size_t *) &msg_sz) : from.receive_message(buf, (size_t *) &msg_sz, &sender_id)) {
  case FileTransportReceiver::RM_OK : {
    break;
  }
  default : goto cleanup;
  }
  
  result = to.send_message(buf, msg_sz, sender_id);
  
  cleanup:
  delete [] buf;
  
  return result;
}

void run_main_loop(FileTransportSender & vhsm_sender,
                   FileTransportReceiver & vhsm_receiver,
                   FileTransportSender & container_sender,
                   FileTransportReceiver & container_receiver) {
  while (!usleep(SLEEP_TIME_USEC)) {
    std::cerr << "forwarding message from container to vhsm... ";
    if (!forward_message(container_receiver, vhsm_sender)) {
      std::cerr << "FAILED" << std::endl;
      return;
    } else {
      std::cerr << "OK" << std::endl;
    }
    
    std::cerr << "forwarding message from vhsm to container... ";
    if (!forward_message(vhsm_receiver, container_sender)) {
      std::cerr << "FAILED" << std::endl;
      return;
    } else {
      std::cerr << "OK" << std::endl;
    }
  }
}

int main(int argc, char ** argv) {
  FileTransportSender vhsm_sender;
  FileTransportReceiver vhsm_receiver;
  FileTransportSender container_sender;
  FileTransportReceiver container_receiver;
  
  if (!vhsm_sender.open(VHSM_IO_OUT) ||
      !vhsm_receiver.open(VHSM_IO_IN) ||
      !container_sender.open(CONTAINER_IO_OUT) ||
      !container_receiver.open(CONTAINER_IO_IN)) {
    std::cerr << "failed to open one or more file for transport." << std::endl;
    return 1;
  }
  
  run_main_loop(vhsm_sender, vhsm_receiver, container_sender, container_receiver);
  
  return !vhsm_sender.close() || !vhsm_receiver.close() || !container_sender.close() || !container_receiver.close();
}

