#include "vhsm.h"

#include <sched.h>
#include <errno.h>
#include <signal.h>
#include <iostream>

void exit_app(int sig) {
    exit(0);
}

int main(int argc, char *argv[]) {
    struct sigaction sa;
    sa.sa_handler = exit_app;
    sa.sa_mask.__val[0] = 0;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    std::string storageRoot = argc == 2 ? argv[1] : "./data";

    VHSM vhsm(storageRoot);

    int res = vhsm.run();
    switch(res) {
    case VHSM_APP_STORAGE_ERROR:
        std::cerr << "Unable to start vhsm: unable to open database" << std::endl;
        break;
    case VHSM_APP_TRANSPORT_ERROR:
        std::cerr << "Unable to start vhsm: unable to open transport" << std::endl;
        break;
    default: break;
    }

    return res;

}
