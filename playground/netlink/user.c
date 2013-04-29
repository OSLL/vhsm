#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>


struct sockaddr_nl src_addr;
int nl_socket;

int main(int argc, char **argv)
{
        int i = 10;

        nl_socket = socket(AF_NETLINK, SOCK_RAW, 21);
        if ( nl_socket == -1 )
        {
            printf("create error");
            return 0;
        }


        memset(&src_addr, 0, sizeof(src_addr));
        src_addr.nl_family = AF_NETLINK;
        src_addr.nl_pid = getpid();
        src_addr.nl_groups = 0;

        if ( bind(nl_socket, (struct sockaddr *)&src_addr, sizeof(src_addr)) == -1 )
        {
             printf("bind error");
             return 0;
        }

         if ( write(nl_socket, &i, sizeof(i)) == -1 )
         {
              printf("write error");
              return 0;
         }
         close(nl_socket);

}
