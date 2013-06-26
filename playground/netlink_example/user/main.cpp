#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

struct nl_socket {
    int fd;
    sockaddr_nl addr;
};

int main(int argc, char *argv[]) {
    nl_socket src_sock;
    src_sock.fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_USERSOCK);
    if(src_sock.fd < 0) {
        printf("Unable to create socket\n");
        return 0;
    }

    src_sock.addr.nl_family = AF_NETLINK;
    src_sock.addr.nl_pid = getpid();
    src_sock.addr.nl_groups = 0;

    int res = bind(src_sock.fd, (sockaddr*)&src_sock.addr, sizeof(src_sock.addr));
    if(res < 0) {
        printf("Unable to bind socket\n");
        return 0;
    }

    sockaddr_nl dst_addr;
    dst_addr.nl_family = AF_NETLINK;
    dst_addr.nl_pid = 0;
    dst_addr.nl_groups = 0;

    nlmsghdr *nlh = (nlmsghdr*)malloc(NLMSG_SPACE(1024));
    memset(nlh, 0, NLMSG_SPACE(1024));
    nlh->nlmsg_len = NLMSG_SPACE(1024);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy((char*)NLMSG_DATA(nlh), "hello\0");

    res = sendto(src_sock.fd, nlh, nlh->nlmsg_len, 0, (sockaddr*)&dst_addr, sizeof(dst_addr));
    if(res < 0) {
        printf("error: %d\n", errno);
        return 0;
    }
    printf("Ret: %d\n", res);

    char buf[NLMSG_SPACE(1024)];
    recvfrom(src_sock.fd, buf, NLMSG_SPACE(1024), 0, NULL, NULL);
    nlmsghdr *rnlh = (nlmsghdr*)buf;
    printf("Received message payload: %s\n", NLMSG_DATA(rnlh));

    close(src_sock.fd);

    return 0;
}
