#include "vhsm.h"

#include <sched.h>
#include <errno.h>
#include <signal.h>

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

    vhsm.run();

    return 0;

}
