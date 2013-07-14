//#include "EncryptedStorageFactory.h"

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

/*
ES::Key generate_key(char const * password) {
  CryptoPP::SHA256 keyHashCtx;
  byte keyHash[32];
  keyHashCtx.Update((byte*)password, strlen(password));
  keyHashCtx.Final(keyHash);
  
  ES::Key key(32);
  
  for(size_t i = 0; i < 32; ++i) {
    key[i] = keyHash[i];
  }
  
  return key;
}

void init_root(int nargs, char ** args) {
  if (1 != nargs) {
    show_help();
    return;
  }
  
  ES::EncryptedStorage * es = EncryptedStorageFactory().create_storage(args[0], true);
  delete es;
}

void create_user(int nargs, char ** args) {
  if (3 != nargs) {
    show_help();
    return;
  }
  
  ES::EncryptedStorage * es = EncryptedStorageFactory().create_storage(args[0], false);
  ES::Key key = generate_key(args[2]);
  
  if (!es->create_namespace(args[1], key)) {
    std::cout << "Failed to create namespace" << std::endl;
  }
  
  delete es;
}
*/

void create_user(int argc, char ** argv) {
    if (3 != argc) {
        show_help();
        return;
    }

    VhsmStorage storage(argv[0]);
    if(storage.createUser(argv[1], argv[2])) {
        std::cout << "Unable to create user" << std::endl;
    }
}

void init_root(int argc, char ** argv) {
    if (1 != argc) {
        show_help();
        return;
    }

    std::string path = argv[0];
    mkdir(path.c_str(), 0777);

    std::cout << "Initializing database at: " << path << std::endl;

    VhsmStorage storage(path);
    if(!storage.initDatabase()) {
        std::cout << "Unable to init database" << std::endl;
    }
}

int main(int argc, char ** argv) {
    if (2 >= argc) {
        show_help();
        return 1;
    }

    switch (argv[1][0]) {
    case 'i':
        init_root(argc - 2, argv + 2);
        break;
    case 'c':
        create_user(argc - 2, argv + 2);
        break;
    default :
        show_help();
        return 1;
    }

    return 0;
}
