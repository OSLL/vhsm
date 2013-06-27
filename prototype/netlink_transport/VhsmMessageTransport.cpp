#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>

#include "VhsmMessageTransport.h"

VhsmMessageTransport::VhsmMessageTransport() : opened(false) {
    open();

    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;
}

VhsmMessageTransport::~VhsmMessageTransport() {
    this->close();
}

bool VhsmMessageTransport::open() {
    if(opened) return false;
    sock.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if(sock.fd < 0) {
        std::cerr << "Unable to create socket" << std::endl;
        opened = false;
        return opened;
    }

    sock.addr.nl_family = AF_NETLINK;
    sock.addr.nl_pid = getpid();
    sock.addr.nl_groups = 0;

    int res = bind(sock.fd, (sockaddr*)&sock.addr, sizeof(sock.addr));
    if(res < 0) {
        std::cerr << "Unable to bind socket: " << res << std::endl;
        opened = false;
        ::close(sock.fd);
        return opened;
    }

    opened = true;
    return opened;
}

void VhsmMessageTransport::close() {
    if(opened) {
        ::close(sock.fd);
        opened = false;
    }
}

//----------------------------------------------------------------

bool VhsmMessageTransport::send_data(const void *data, size_t size, int message_type, int pid, int veid) const {
    if(!opened) return false;

    size_t real_msg_size = NLMSG_SPACE(sizeof(vmsghdr) + size);
    nlmsghdr *nlh = (nlmsghdr*)malloc(real_msg_size);
    memset(nlh, 0, real_msg_size);
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(vmsghdr) + size);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    vmsghdr *msgh = (vmsghdr*)NLMSG_DATA(nlh);
    msgh->type = message_type;
    msgh->pid = pid;
    msgh->veid = veid;
    if(data) memcpy((char*)NLMSG_DATA(nlh) + sizeof(vmsghdr), data, size);

    bool res = sendto(sock.fd, nlh, nlh->nlmsg_len, 0, (sockaddr*)&dst_addr, sizeof(dst_addr)) >= 0;

    free(nlh);
    return res;
}

bool VhsmMessageTransport::receive_data(char *buf, size_t *buf_sz_ptr, int *sender_id) const {
    if(!opened) return false;

    char tbuf[MAX_MSG_SIZE];
    size_t ln = recvfrom(sock.fd, tbuf, MAX_MSG_SIZE, 0, NULL, NULL);
    if(ln < EMPTY_MSG_SIZE) {
        std::cerr << "Unable to read message" << std::endl;
        return false;
    }

    *buf_sz_ptr = NLMSG_PAYLOAD((nlmsghdr*)tbuf, 0); //((nlmsghdr*)tbuf)->nlmsg_len - NLMSG_HDRLEN;
    memcpy(buf, NLMSG_DATA(tbuf), *buf_sz_ptr);
    return true;
}
