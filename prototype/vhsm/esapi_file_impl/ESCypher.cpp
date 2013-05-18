#include "ESCypher.h"
#include <iostream>
#include <crypto++/aes.h>
#include <crypto++/modes.h>
#include <crypto++/filters.h>

namespace ES {

bool Cypher::encrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Encryption enc(key.data(), key.size());

    std::string res;
    try {
        CryptoPP::StringSource((const byte*)data, length, true,
                               new CryptoPP::StreamTransformationFilter(enc, new CryptoPP::StringSink(res)));
    } catch(...) {
        return false;
    }

    if(res_length) *res_length = res.size();
    *result = new char[res.size()];
    memcpy(*result, res.data(), res.size());

    return true;
}

bool Cypher::decrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length) {
    CryptoPP::ECB_Mode<CryptoPP::AES>::Decryption dec(key.data(), key.size());

    std::string res;
    try {
        CryptoPP::StringSource((const byte*)data, length, true,
                               new CryptoPP::StreamTransformationFilter(dec, new CryptoPP::StringSink(res)));
    } catch(CryptoPP::InvalidCiphertext e) {
        std::cout << e.what() << std::endl;
        return false;
    }

    if(res_length) *res_length = res.size();
    *result = new char[res.size()];
    memcpy(*result, res.data(), res.size());

    return true;
}


}
