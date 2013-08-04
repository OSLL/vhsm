#include <iostream>
#include <cstring>
#include <sys/stat.h>

#include "VhsmStorage.h"

void show_help() {
    std::cout << "VHSM admin tool." << std::endl;
    std::cout << "\tUsage: ./vhsm_admin <cmd> [args]" << std::endl;
    std::cout << "Commands:" << std::endl;
    std::cout << "\ti <storage_root> - initialize storage root at given path" << std::endl;
    std::cout << "\tc <storage_root> <username> <password> - create user with given username and password" << std::endl;
}

int create_user(int argc, char ** argv) {
    if (3 != argc) {
        show_help();
        return 1;
    }

    VhsmStorage storage(argv[0]);
    if(storage.createUser(argv[1], argv[2])) {
        std::cout << "Unable to create user" << std::endl;
        return 1;
    }
    return 0;
}

int init_root(int argc, char ** argv) {
    if (1 != argc) {
        show_help();
        return 1;
    }

    std::string path = argv[0];
    mkdir(path.c_str(), 0777);

    std::cout << "Initializing database at: " << path << std::endl;

    VhsmStorage storage(path);
    if(!storage.initDatabase()) {
        std::cout << "Unable to init database" << std::endl;
        return 1;
    }
    return 0;
}

int main(int argc, char ** argv) {
    if (2 >= argc) {
        show_help();
        return 1;
    }

    switch (argv[1][0]) {
    case 'i':
        return init_root(argc - 2, argv + 2);
    case 'c':
        return create_user(argc - 2, argv + 2);
    default :
        show_help();
        return 1;
    }
}
