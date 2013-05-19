#include <stdio.h>
#include <stdlib.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#define ENGINE_MODULE "/home/user/work/vhsm/prototype/test_drive/1/test_engine.so"
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
    ENGINE_ctrl_cmd_string(e, "username", "user", 0);
    ENGINE_ctrl_cmd_string(e, "password", "password", 0);
    ENGINE_init(e);
    
    HMAC_CTX ctx;
    HMAC_CTX_init(&ctx);
    HMAC_Init_ex(&ctx, "test_key\0", 9, EVP_sha1(), e);

    FILE *f = fopen(argv[1], "r");
    char buf[BUF_SIZE];
    while(!feof(f)) {
        size_t ln = fread(buf, sizeof(char), BUF_SIZE, f);
        if(ln == 0) continue;
        HMAC_Update(&ctx, buf, ln);
    }
    fclose(f);
    
    unsigned int siglen;
    unsigned char md[20];
    HMAC_Final(&ctx, md, &siglen);
    ENGINE_finish(e);

    printf("HMAC-SHA1: ");
    for(size_t i = 0; i < siglen; i++) printf("%02x", md[i]);
    printf("\n");

    return 0;
}
