#include <iostream>
#include <cstring>
#include <cstdio>
#include <crypto++/hmac.h>
#include <crypto++/sha.h>
#include <crypto++/hex.h>
#include <openssl/hmac.h>

#define BUF_SIZE 4096

void print_md(const char *prefix, const byte *md, size_t mdlen) {
    printf("%s", prefix);
    for(size_t i = 0; i < mdlen; ++i) printf("%02x", md[i]);
    printf("\n");
}

int main(int argc, char *argv[]) {
    if(argc != 3) {
        std::cout << "Usage: cryptopp_test <key> <file>" << std::endl;
        return -1;
    }

    CryptoPP::HMAC<CryptoPP::SHA1> hmac((const byte *)argv[1], strlen(argv[1]));

    byte buf[BUF_SIZE];
    FILE *in = fopen(argv[2], "r");
    if(!in) {
        std::cout << "Unable to open file: " << argv[2] << std::endl;
        return -1;
    }

    HMAC_CTX hctx;
    HMAC_CTX_init(&hctx);
    HMAC_Init_ex(&hctx, argv[1], strlen(argv[1]), EVP_sha1(), 0);

    while(feof(in)) {
        size_t len = fread(buf, 1, BUF_SIZE, in);
        if(len > 0) {
            hmac.Update(buf, len);
            HMAC_Update(&hctx, buf, len);
        }
    }
    fclose(in);

    byte cppmd[20], sslmd[20];
    hmac.Final(cppmd);
    HMAC_Final(&hctx, sslmd, 0);
    HMAC_CTX_cleanup(&hctx);

/*  Just another way to convert in hex form

    std::string hcppmd;
    CryptoPP::StringSource(cppmd, 20, true, new CryptoPP::HexEncoder(new CryptoPP::StringSink(hcppmd), false));
*/

    print_md("HMAC-SHA1 (Crypto++): ", cppmd, 20);
    print_md("HMAC-SHA1 (OpenSSL):  ", sslmd, 20);

    return 0;
}

