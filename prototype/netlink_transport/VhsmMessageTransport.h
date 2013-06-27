#ifndef VHSM_MESSAGE_TRANSPORT_H
#define VHSM_MESSAGE_TRANSPORT_H

#include <sys/socket.h>
#include <linux/netlink.h>
#include <stdint.h>

#define VHSM_REQUEST    0
#define VHSM_RESPONSE   1
#define VHSM_ERROR      2
#define VHSM_REGISTER   3
#define VHSM_INFO       4

struct vmsghdr {
    int type;
    uint32_t veid;
    uint32_t pid;
};

#define MAX_MSG_SIZE    4096
#define MAX_DATA_LENGTH (4096 - NLMSG_HDRLEN - sizeof(vmsghdr))
#define EMPTY_MSG_SIZE  NLMSG_HDRLEN
#define GET_MSG_DATA(msg)   (char*)((char*)msg + sizeof(vmsghdr))

class VhsmMessageTransport {
public:
    VhsmMessageTransport();
    ~VhsmMessageTransport();
    
    bool open();
    void close();

    bool is_opened() const {
        return opened;
    }

    bool send_data(const void *data, size_t size, int message_type, int pid = 0, int veid = 0) const;
    bool receive_data(char *buf, size_t *buf_sz_ptr, int *sender_id = 0) const;

private:
    struct nl_socket {
        int fd;
        sockaddr_nl addr;
    };

    sockaddr_nl dst_addr;
    nl_socket sock;
    bool opened;
};

#endif
