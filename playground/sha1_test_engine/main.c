#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>

#define TEST_ENGINE_ID "test_engine"
#define TEST_ENGINE_NAME "Test Engine"

#define CMD_SO_PATH         ENGINE_CMD_BASE
#define CMD_MODULE_PATH 	(ENGINE_CMD_BASE+1)
#define CMD_PIN             (ENGINE_CMD_BASE+2)

static const ENGINE_CMD_DEFN te_cmd_defns[] = {
    {CMD_SO_PATH, "SO_PATH", "Specifies the path to the 'pkcs11-engine' shared library", ENGINE_CMD_FLAG_STRING},
    {CMD_MODULE_PATH, "MODULE_PATH", "Specifies the path to the pkcs11 module shared library", ENGINE_CMD_FLAG_STRING},
    {CMD_PIN, "PIN", "Specifies the pin code", ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

//-----------------------------------------------------------------------------
//Internal implemetation of the algorithm

static int te_digest_init(EVP_MD_CTX *ctx);
static int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int te_digest_final(EVP_MD_CTX *ctx,unsigned char *md);
static int te_digest_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from);
static int te_digest_cleanup(EVP_MD_CTX *ctx);
static int te_digest_ctrl(EVP_MD_CTX *ctx,int type, int arg, void *ptr);

struct te_hmac_sha1_digest_ctx {
    char uid[32];
    int uid_set;
    int final;
};

EVP_MD digest_hmac_sha1 = {
    NID_sha1,               //nid of the algorithm
    NID_undef,              //private key type. It must be NID_undef for unknown reason
    20,                     //size of signature in bytes
    0,                      //flags, unknown
    te_digest_init,
    te_digest_update,
    te_digest_final,
    te_digest_copy,
    te_digest_cleanup,
    NULL,
    NULL,
    {0,0,0,0,0},
    64,                     //block size in bytes, for SHA1 should be 64
    sizeof(struct te_hmac_sha1_digest_ctx),
    NULL                    //digest control function
};

//-----------------------------------------------------------------------------
//Backend functions

struct REMOTE_HMAC_CTX {
    HMAC_CTX hctx;
    char uid[32];
    int ready;
};

static struct REMOTE_HMAC_CTX remote_ctx;

#define CREATE_IPAD 1
#define CREATE_OPAD 2
#define UPDATE_HASH 3
#define FINAL_START 4
#define FINAL_END   5

static int identify(const char *uid, size_t uid_ln) {
    if(!strncmp("123", uid, 3)) return 1;
    return 0;
}

static int init_remote_ctx() {
    if(!remote_ctx.ready) {
        remote_ctx.ready = 1;
        HMAC_CTX_init(&remote_ctx.hctx);
    }
    return 1;
}

static int update_remote_ctx(const char *uid, size_t uid_ln, int phase, const void *data, size_t count) {
    if(!identify(uid, uid_ln)) return 0;
    //here we must extract real key for the given uid
    //this code is here just for example
    char real_key[64];
    memset(real_key, 0, 64);
    strcpy(real_key, "user_123_key");

    char pad[64];
    switch(phase) {
    case CREATE_IPAD:
        for(int i = 0; i<64; i++) pad[i] = 0x36^real_key[i];
        if(!EVP_DigestInit_ex(&remote_ctx.hctx.i_ctx, EVP_sha(), 0)) return 0;
        if(!EVP_DigestUpdate(&remote_ctx.hctx.i_ctx, pad, EVP_MD_block_size(EVP_sha()))) return 0;
        if(!EVP_MD_CTX_copy_ex(&remote_ctx.hctx.md_ctx, &remote_ctx.hctx.i_ctx)) return 0;
        return 1;
    case CREATE_OPAD:
        for(int i = 0; i<64; i++) pad[i] = 0x5c^real_key[i];
        if(!EVP_DigestInit_ex(&remote_ctx.hctx.o_ctx, EVP_sha(), 0)) return 0;
        if(!EVP_DigestUpdate(&remote_ctx.hctx.o_ctx, pad, EVP_MD_block_size(EVP_sha()))) return 0;
        return 1;
    case UPDATE_HASH:
        return EVP_DigestUpdate(&remote_ctx.hctx.md_ctx, data, count);
    }
    return 0;
}

static int final_remote_ctx(const char *uid, size_t uid_ln, int phase, unsigned char *md) {
    if(!identify(uid, uid_ln)) return 0;
    unsigned int len;
    switch(phase) {
    case FINAL_START:
        if (!EVP_DigestFinal_ex(&remote_ctx.hctx.md_ctx, md, &len)) return 0;
        if (!EVP_MD_CTX_copy_ex(&remote_ctx.hctx.md_ctx, &remote_ctx.hctx.o_ctx)) return 0;
        return 1;
    case FINAL_END: {
        int res = EVP_DigestFinal_ex(&remote_ctx.hctx.md_ctx, md, &len);
        //maybe here we should make cleanup
        HMAC_CTX_cleanup(&remote_ctx.hctx);
        return res;
    }
    }
    return 0;
}

//-----------------------------------------------------------------------------
//Internal SHA1 implementation

int te_digest_init(EVP_MD_CTX *ctx) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    c->uid_set = 0;
    c->final = 0;
    init_remote_ctx();
    return 1;
}

int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    if(c->uid_set == 0) {
        for (int i = 0; i < 32; i++) c->uid[i] = 0x36^((const char*)data)[i];
        if(!identify(c->uid, 32)) {
            for (int i = 0; i < 32; i++) c->uid[i] = 0x5c^((const char*)data)[i];
            if(!identify(c->uid, 32)) {
                //unknown user
                return 0;
            } else {
                c->uid_set = 1;
                c->final = 1;
                return update_remote_ctx(c->uid, 32, CREATE_OPAD, 0, 0);
            }
        } else {
            c->uid_set = 1;
            return update_remote_ctx(c->uid, 32, CREATE_IPAD, 0, 0);
        }
    } else {
        return update_remote_ctx(c->uid, 32, UPDATE_HASH, data, count);
    }
}

int te_digest_final(EVP_MD_CTX *ctx, unsigned char *md) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    if(!c->uid_set) return 0;
    if(!c->final) return final_remote_ctx(c->uid, 32, FINAL_START, md);
    else return final_remote_ctx(c->uid, 32, FINAL_END, md);
}

int te_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) {
    if (to->md_data && from->md_data) {
        memcpy(to->md_data, from->md_data, sizeof(struct te_hmac_sha1_digest_ctx));
    }
    return 1;
}

int te_digest_cleanup(EVP_MD_CTX *ctx) {
    if (ctx->md_data) {
        struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
        memset(ctx->md_data, 0, sizeof(struct te_hmac_sha1_digest_ctx));
    }
    return 1;
}

//------------------------------------------------------------------
//Digest algorithms provided by the engine

static int test_engine_digest_nids[] = {NID_sha1, 0};

static int te_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid) {
    if (!digest) {
        *nids = test_engine_digest_nids;
        return 1;
    }
    if(nid == NID_sha1) {
        *digest = &digest_hmac_sha1;
        return 1;
    } else {
        *digest = NULL;
        return 0;
    }
}

//------------------------------------------------------------------
//Engine commands control

static int test_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ()) {
    switch (cmd) {
    case CMD_MODULE_PATH:
        printf("MODULE_PATH called: %s\n", (const char *)p);
        return 1;
    default:
        break;
    }
    return 0;
}

//------------------------------------------------------------------
//Engine setup

static int bind_helper(ENGINE * e) {
    if (!ENGINE_set_id(e, TEST_ENGINE_ID)
        || !ENGINE_set_name(e, TEST_ENGINE_NAME)
        || !ENGINE_set_ctrl_function(e, test_engine_ctrl)
        || !ENGINE_set_cmd_defns(e, te_cmd_defns)
        || !ENGINE_set_digests(e, te_digests)) {
        printf("Engine init failed\n");
        return 0;
    }

    if(!ENGINE_register_digests(e)
        || !EVP_add_digest(&digest_hmac_sha1)) {
        printf("Digest registration failed\n");
        return 0;
    }

    return 1;
}

static int bind_fn(ENGINE * e, const char *id) {
    if (id && (strcmp(id, TEST_ENGINE_ID) != 0)) {
        fprintf(stderr, "bad engine id\n");
        return 0;
    }
    if (!bind_helper(e)) {
        fprintf(stderr, "bind failed\n");
        return 0;
    }
    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)
