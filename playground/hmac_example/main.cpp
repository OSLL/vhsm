#include <iostream>
#include <iomanip>
#include <string>
#include <openssl/engine.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <algorithm>

char* getCmdOption(char ** begin, char ** end, const std::string & option)
{
    char ** itr = std::find(begin, end, option);
    if (itr != end && ++itr != end)
    {
        return *itr;
    }
    return 0;
}

bool cmdOptionExists(char** begin, char** end, const std::string& option)
{
    return std::find(begin, end, option) != end;
}



int load_engine(const char * name)
{

    ENGINE *engine;

    engine = ENGINE_by_id(name);

    if (engine == NULL) {
        std::cerr <<  "ENGINE_by_id(\""<<name<<"\") failed";
        return -1;
    }

    if (ENGINE_set_default(engine, ENGINE_METHOD_ALL) == 0) {
       std::cerr << "ENGINE_set_default(\""<<name<<"\", ENGINE_METHOD_ALL) failed";

        ENGINE_free(engine);

        return -1;
    }

    ENGINE_free(engine);

    return 0;
}


int main (int argc, char *argv[])
{
    const char* engine = getCmdOption(argv, argv + argc, "-e");
    char* data = getCmdOption(argv, argv + argc, "-d");
    char* key = getCmdOption(argv, argv + argc, "-k");
    unsigned int result_len=40;

    if (engine)
    {
        if(load_engine(engine))
            return 0;
    }

    if(!key)
    {
        key = new char[9];
        std::fill_n(key,9,0);
        strcpy(key,"Password");
    }
    if(!data)
    {
        data = new char[8];
        std::fill_n(data,8,0);
        strcpy(data,"Message");
    }

    HMAC_CTX ctx;
    unsigned char* result = (unsigned char*) malloc(sizeof(char) * result_len);

    HMAC_CTX_init(&ctx);

    HMAC_Init_ex(&ctx, key, strlen(key), EVP_sha1(), NULL);
    HMAC_Update(&ctx, (const unsigned char*)data, strlen(data));
    HMAC_Final(&ctx, result, &result_len);
    HMAC_CTX_cleanup(&ctx);



 for(size_t i=0;i<result_len;i++)
    std::cout << std::setfill('0') << std::setw(2) << std::hex << (int)result[i];

}

