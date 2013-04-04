#include <stdio.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/evp.h>

#define ENGINE_MODULE "/home/user/work/openssl_engine_test/test_engine.so"
#define BUF_SIZE 4096

//--------------------------------------------------------
//This function loads the specified dynamic engine
//so_path must be equals to the path specified in openssl.cnf
//see http://osll.spb.ru/issues/4015

ENGINE *load_engine(const char *so_path, const char *id) {
    ENGINE_load_dynamic();
    ENGINE *de = ENGINE_by_id("dynamic");
    if(de == 0) {
        printf("Unable to load dynamic engine\n");
        return 0;
    }

    if(!ENGINE_ctrl_cmd_string(de, "SO_PATH", so_path, 0)) {
        printf("Unable to load desired engine\n");
        return 0;
    }
    ENGINE_ctrl_cmd_string(de, "LIST_ADD", "2", 0);
    ENGINE_ctrl_cmd_string(de, "LOAD", NULL, 0);
    ENGINE_free(de);
    return ENGINE_by_id(id);
}

//--------------------------------------------------------
//This function sets private key. In this sample it's a real key
//Required by digest algorithm

int set_private_key(const char *uid, EVP_PKEY **sigkey, ENGINE *e) {
    if(!*sigkey) *sigkey = EVP_PKEY_new();

    EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new_id(NID_hmac_sha1, e);
    EVP_PKEY_keygen_init(pkey_ctx);
    EVP_PKEY_CTX_ctrl_str(pkey_ctx, "uid", uid);
    EVP_PKEY_keygen(pkey_ctx, sigkey);
    EVP_PKEY_CTX_free(pkey_ctx);

    return 1;
}

//--------------------------------------------------------
//HMAC-SHA1 function. Simple realization without error checking

int hmac_sha1(const char *file, EVP_PKEY *sigkey, ENGINE *e, unsigned char *md, size_t *siglen) {
    FILE *f = fopen(file, "r");
    if(!f) {
        printf("Unable to open input file\n");
        return 0;
    }

    const EVP_MD *hmac = ENGINE_get_digest(e, NID_hmac_sha1);
    EVP_MD_CTX *mctx = EVP_MD_CTX_create();
    EVP_PKEY_CTX *pctx = NULL;
    EVP_DigestSignInit(mctx, &pctx, hmac, e, sigkey);

    char buf[BUF_SIZE];
    while(!feof(f)) {
        size_t ln = fread(buf, sizeof(char), BUF_SIZE, f);
        if(ln == 0) continue;
        EVP_DigestSignUpdate(mctx, buf, ln);
    }
    fclose(f);

    EVP_DigestSignFinal(mctx, md, siglen);
    return 1;
}

//--------------------------------------------------------

int main(int argc, char *argv[]) {
    if(argc != 2) {
        printf("Usage: ./test_app <file_name>\n");
        return -1;
    }

    ENGINE *e = load_engine(ENGINE_MODULE, "test_engine");
    if(e == 0) {
        printf("Unable to load engine\n");
        return -1;
    }
    ENGINE_init(e);

    EVP_PKEY *sigkey = NULL;
    set_private_key("123", &sigkey, e);

    size_t siglen;
    unsigned char md[20];
    if(!hmac_sha1(argv[1], sigkey, e, md, &siglen)) {
        EVP_PKEY_free(sigkey);
        ENGINE_finish(e);
        return -1;
    }

    EVP_PKEY_free(sigkey);
    ENGINE_finish(e);

    printf("HMAC-SHA1: ");
    for(size_t i = 0; i < siglen; i++) printf("%02x", md[i]);
    printf("\n");

    return 0;
}
