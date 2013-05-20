#include "ESCypher.h"
#include <iostream>
#include <crypto++/aes.h>
#include <crypto++/gcm.h>
#include <crypto++/filters.h>
#include <crypto++/osrng.h>

namespace ES {

static const int IV_SIZE = CryptoPP::AES::BLOCKSIZE * 16;

bool Cypher::encrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length) {
    CryptoPP::AutoSeededRandomPool prng;

    byte iv[IV_SIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    CryptoPP::GCM<CryptoPP::AES>::Encryption enc;
    enc.SetKeyWithIV(key.data(), key.size(), iv, IV_SIZE);

    std::string encres;
    try {
        CryptoPP::StringSource((const byte*)data, length, true,
                               new CryptoPP::AuthenticatedEncryptionFilter(enc, new CryptoPP::StringSink(encres), false)
                              );
    } catch(...) {
        return false;
    }

    std::string res((const char*)iv, IV_SIZE);
    res.append(encres);

    if(res_length) *res_length = res.size();
    *result = new char[res.size()];
    memcpy(*result, res.data(), res.size());

    return true;
}

bool Cypher::decrypt(const char *data, size_t length, const Key &key, char **result, size_t *res_length) {
    CryptoPP::GCM<CryptoPP::AES>::Decryption dec;
    dec.SetKeyWithIV(key.data(), key.size(), (const byte *)data, IV_SIZE);

    std::string decres;
    CryptoPP::AuthenticatedDecryptionFilter df(dec, new CryptoPP::StringSink(decres));

    CryptoPP::StringSource((const byte*)data + IV_SIZE,
                           length - IV_SIZE,
                           true,
                           new CryptoPP::Redirector(df)
                          );

    if(df.GetLastResult() != true) return false;

    if(res_length) *res_length = decres.size();
    *result = new char[decres.size()];
    memcpy(*result, decres.data(), decres.size());

    return true;
}


}
