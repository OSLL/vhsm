#include <iostream>
#include <fstream>
#include <keyczar/keyczar.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[]) {
    if(argc != 2) {
        std::cout << "Usage: ketczar_test <file>" << std::endl;
        return -1;
    }

    keyczar::Keyczar *signer = keyczar::Signer::Read("kc_keys");
    if(!signer) {
        std::cout << "Unable to read keys" << std::endl;
        return -1;
    }

    std::string msg;
    std::ifstream in(argv[1]);
    char buf[BUF_SIZE];
    if(!in.is_open()) {
        std::cout << "Unable to open file " << argv[1] << std::endl;
        return -1;
    }
    while(!in.eof()) {
        in.read(buf, BUF_SIZE);
        msg.append(buf);
    }
    in.close();

/*  The way we can extract keys
    std::string key;
    ((DictionaryValue*)signer->keyset()->GetKey(1)->GetValue())->GetString("hmacKeyString", &key);
*/

    //signer->set_encoding(keyczar::Keyczar::NO_ENCODING);
    std::cout << "HMAC-SHA1 (keyczar base64): " << signer->Sign(msg) << std::endl;
    return 0;
}
