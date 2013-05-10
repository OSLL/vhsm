#pragma once

struct FileTransportMessage {
  int sender_id;
  size_t msg_size;
  char msg[0];
};
