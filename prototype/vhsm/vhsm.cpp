#include <iostream>

#include "vhsm.h"

VHSM::VHSM() {
    transport.send_data(NULL, 0, VHSM_REGISTER);
}

VHSM::~VHSM() {
}

void VHSM::run() {
    VhsmMessage msg;
    ClientId cid;

    while(true) {
        if(!read_message(msg, cid)) continue;

        if(!send_response(handleMessage(msg, cid), cid)) {
            std::cerr << "Unable to send response to veid: " << cid.veid << " pid: " << cid.pid << std::endl;
        }
    }
}

bool VHSM::read_message(VhsmMessage &msg, ClientId &cid) const {
    char buf[MAX_MSG_SIZE];
    size_t buf_size = MAX_MSG_SIZE;

    if(!transport.receive_data(buf, &buf_size)) {
        std::cerr << "unable to read data from socket" << std::endl;
        return false;
    }

    vmsghdr *msgh = (vmsghdr*)buf;
    if(msgh->type != VHSM_REQUEST) {
        std::cerr << "wrong message type" << std::endl;
        return false;
    }

    cid.pid = msgh->pid;
    cid.veid = msgh->veid;

    char *msg_data = (char*)(buf + sizeof(vmsghdr));
    bool res = msg.ParseFromArray(msg_data, buf_size - sizeof(vmsghdr));
    if (!res) std::cerr << "ill-formed message received" << std::endl;
    return res;
}

bool VHSM::send_response(const VhsmResponse &response, const ClientId &cid) const {
    size_t buf_size = response.ByteSize();
    char *buf = new char[buf_size];

    bool res = false;
    if (response.SerializeToArray(buf, buf_size)) {
        res = transport.send_data(buf, buf_size, VHSM_RESPONSE, cid.pid, cid.veid);
    }

    if (buf) delete[] buf;
    return res;
}

//----------------------------------------------------------------

int main(int argc, char *argv[]) {
    VHSM vhsm;
    vhsm.run();
    return 0;
}

/*

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

*/
