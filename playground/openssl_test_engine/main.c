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

//------------------------------------------------------------------
//These functions tells openssl what algorithms with private keys our engine provides

static int test_engine_pkey_meth_nids[] = {NID_hmac_sha1, 0 };
static EVP_PKEY_METHOD *pmeth_HMAC_SHA1 = NULL;
static EVP_PKEY_ASN1_METHOD *ameth_HMAC_SHA1 = NULL;

static int te_pkey_meths (ENGINE *e, EVP_PKEY_METHOD **pmeth, const int **nids, int nid) {
    if (!pmeth) {
        *nids = test_engine_pkey_meth_nids;
        return 1;   //number of nids in array
    }
    if(nid == NID_hmac_sha1) {
        *pmeth = pmeth_HMAC_SHA1;
        return 1;
    } else {
        *pmeth = NULL;
        return 0;
    }
}

static int te_pkey_asn1_meths(ENGINE *e, EVP_PKEY_ASN1_METHOD **ameth,	const int **nids, int nid) {
    if (!ameth) {
        *nids = test_engine_pkey_meth_nids;
        return 1;   //number of nids in array
    }
    if(nid == NID_hmac_sha1) {
        *ameth = ameth_HMAC_SHA1;
        return 1;
    } else {
        *ameth = NULL;
        return 0;
    }
}

//-----------------------------------------------------------------------------
//Internal implemetation of the algorithm

static int te_digest_init(EVP_MD_CTX *ctx);
static int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int te_digest_final(EVP_MD_CTX *ctx,unsigned char *md);
static int te_digest_copy(EVP_MD_CTX *to,const EVP_MD_CTX *from);
static int te_digest_cleanup(EVP_MD_CTX *ctx);
static int te_digest_ctrl(EVP_MD_CTX *ctx,int type, int arg, void *ptr);

struct te_hmac_sha1_digest_ctx {
    char key[32];
    char key_ln;
    int key_set;
    HMAC_CTX hctx;
};

#define EVP_MD_CTRL_KEY_LEN (EVP_MD_CTRL_ALG_CTRL+3)
#define EVP_MD_CTRL_SET_KEY (EVP_MD_CTRL_ALG_CTRL+4)

EVP_MD digest_hmac_sha1 = {
    NID_hmac_sha1,          //nid of the algorithm
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
    te_digest_ctrl
};

int te_digest_ctrl(EVP_MD_CTX *ctx, int type, int arg, void *ptr) {
    switch (type) {
    case EVP_MD_CTRL_KEY_LEN:
        printf("Key length called\n");
        *((unsigned int*)(ptr)) = 32;
        return 1;
    case EVP_MD_CTRL_SET_KEY: {
        printf("Set key called: %s\n", (char*)ptr);          //invoked by EVP_PKEY_CTRL_DIGESTINIT command
        struct te_hmac_sha1_digest_ctx *dctx = ctx->md_data;
        memcpy(dctx->key, ptr, arg);
        dctx->key_ln = arg;
        dctx->key_set = 1;
        return 1;
    }
    default:
        return 0;
    }
}

//These functions should be replaced with VHMS API calls
int te_digest_init(EVP_MD_CTX *ctx) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    printf("Digest init. Current key: %s\n", c->key);
    HMAC_CTX_init(&c->hctx);
    HMAC_Init_ex(&c->hctx, c->key, c->key_ln, EVP_sha1(), 0);
    return 1;
}

int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    printf("Digest update. Current key: %s, count: %d\n", c->key, (int)count);
    return HMAC_Update(&c->hctx, data, count);
}

int te_digest_final(EVP_MD_CTX *ctx, unsigned char *md) {
    struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
    unsigned int len;
    printf("Digest final\n");
    int res = HMAC_Final(&c->hctx, md, &len);
    return res;
}

int te_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) {
    if (to->md_data && from->md_data) {
        memcpy(to->md_data, from->md_data, sizeof(struct te_hmac_sha1_digest_ctx));
    }
    return 1;
}

int te_digest_cleanup(EVP_MD_CTX *ctx) {
    printf("Cleaning up\n");
    if (ctx->md_data) {
        struct te_hmac_sha1_digest_ctx *c = ctx->md_data;
        HMAC_CTX_cleanup(&c->hctx);
        memset(ctx->md_data, 0, sizeof(struct te_hmac_sha1_digest_ctx));
    }
    return 1;
}

//-------------------------------------------------------------------
//ameth functions. Currently unknown purpose

static void  mackey_free_gost(EVP_PKEY *pk)	{
    if(pk->pkey.ptr) OPENSSL_free(pk->pkey.ptr);
}

static int mac_ctrl_gost(EVP_PKEY *pkey, int op, long arg1, void *arg2) {
    if (op == ASN1_PKEY_CTRL_DEFAULT_MD_NID) {
        *(int *)arg2 = NID_hmac_sha1;
        return 2;
    }
    return -2;
}

int register_ameth_gost (int nid, EVP_PKEY_ASN1_METHOD **ameth, const char* pemstr, const char* info) {
    *ameth = EVP_PKEY_asn1_new(nid, ASN1_PKEY_SIGPARAM_NULL, pemstr, info);
    if (!*ameth) return 0;
    if(nid == NID_hmac_sha1) {
        EVP_PKEY_asn1_set_free(*ameth, mackey_free_gost);
        EVP_PKEY_asn1_set_ctrl(*ameth, mac_ctrl_gost);
    }
    return 1;
}

//-------------------------------------------------------------------
//Functions that deals with private keys

static int pkey_gost_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2);
static int pkey_gost_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value);
static int pkey_gost_mac_init(EVP_PKEY_CTX *ctx);
static int pkey_gost_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey);
static int pkey_gost_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx);
static int pkey_gost_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx);
static int pkey_gost_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src);
static void pkey_gost_mac_cleanup (EVP_PKEY_CTX *ctx);

//This function tells openssl what pkey operations are supported by our engine for specific algorithm
int register_pmeth_gost(int id, EVP_PKEY_METHOD **pmeth, int flags) {
    *pmeth = EVP_PKEY_meth_new(id, flags);
    if (!*pmeth) return 0;
    if (id == NID_hmac_sha1) {
        EVP_PKEY_meth_set_ctrl(*pmeth, pkey_gost_mac_ctrl, pkey_gost_mac_ctrl_str);             //required if algorithm supports commands
        EVP_PKEY_meth_set_signctx(*pmeth, pkey_gost_mac_signctx_init, pkey_gost_mac_signctx);   //required - sets resulting sign in context
        EVP_PKEY_meth_set_keygen(*pmeth, NULL, pkey_gost_mac_keygen);                           //required - sets (or generates) pkey
        EVP_PKEY_meth_set_init(*pmeth, pkey_gost_mac_init);                                     //required - creates context
        EVP_PKEY_meth_set_cleanup(*pmeth, pkey_gost_mac_cleanup);
        EVP_PKEY_meth_set_copy(*pmeth,pkey_gost_mac_copy);
        return 1;
    }
    return 0;
}

//------------------------------------------------------------------
//Private key operations

//Within engine we can operate with custom pkey data structures
struct te_mac_pmeth_data {
    int key_set;
    int key_ln;
    EVP_MD *md;
    unsigned char uid[32];
    unsigned char key[32];
};

//Init private key data structure
static int pkey_gost_mac_init(EVP_PKEY_CTX *ctx) {
    struct te_mac_pmeth_data *data;
    data = OPENSSL_malloc(sizeof(struct te_mac_pmeth_data));
    if (!data) return 0;
    memset(data, 0, sizeof(struct te_mac_pmeth_data));
    EVP_PKEY_CTX_set_data(ctx, data);
    return 1;
}

//We can control the state of our engine by commands
static int pkey_gost_mac_ctrl(EVP_PKEY_CTX *ctx, int type, int p1, void *p2) {
    struct te_mac_pmeth_data *data = (struct te_mac_pmeth_data*)EVP_PKEY_CTX_get_data(ctx);
    switch (type) {
    case EVP_PKEY_CTRL_MD:
        if (EVP_MD_type((const EVP_MD *)p2) != NID_hmac_sha1) {
            printf("Error: unsupported digest type\n");
            return 0;
        }
        data->md = (EVP_MD*)p2;
        return 1;
    case EVP_PKEY_CTRL_PKCS7_ENCRYPT:
    case EVP_PKEY_CTRL_PKCS7_DECRYPT:
    case EVP_PKEY_CTRL_PKCS7_SIGN:
        return 1;
    case EVP_PKEY_CTRL_SET_MAC_KEY:                             //here we can insert pkey extraction
        printf("Got set user id command: %s\n", (char*)p2);     //or save user id for further operations
        if(strcmp((char*)p2, "123")) {
            printf("Error: unknown user (id = %s)\n", (char*)p2);
            return 0;
        }
        memcpy(data->uid, p2, p1);
        memcpy(data->key, "user_123_key\0", 13);
        data->key_ln = 12;
        data->key_set = 1;
        return 1;
    case EVP_PKEY_CTRL_DIGESTINIT: {                            //this request runs in different context (for unknown reason)
        printf("Got digest init command\n");                    //but has the key that we have installed in keygen request
        void *key = 0;                                          //in this request we must transfer the key into digest context
        int keyln = 0;                                          //so digest must support control commands
        if(!data->key_set) {
            EVP_PKEY *pkey = EVP_PKEY_CTX_get0_pkey(ctx);
            if (!pkey) {
                printf("Error: unable to set key\n");
                return 0;
            }
            key = EVP_PKEY_get0(pkey);
            if (!key) {
                printf("Error: unable to set key\n");
                return 0;
            }
            keyln = strlen((char *)key);    //it's so dangerous
        } else {
            key = &(data->key);
            keyln = data->key_ln;
        }
        return ((EVP_MD_CTX*)p2)->digest->md_ctrl((EVP_MD_CTX*)p2, EVP_MD_CTRL_SET_KEY, keyln, key);
    }
    }
    return -2;
}

//Transforms command string into request
static int pkey_gost_mac_ctrl_str(EVP_PKEY_CTX *ctx, const char *type, const char *value) {
    printf("Got command: %s with arg: %s\n", type, value);
    if (!strcmp(type, "uid")) {
        return pkey_gost_mac_ctrl(ctx, EVP_PKEY_CTRL_SET_MAC_KEY, strlen(value), (char *)value);
    }
    return -2;
}

//Generate or load key. Called very early
static int pkey_gost_mac_keygen(EVP_PKEY_CTX *ctx, EVP_PKEY *pkey) {
    printf("Keygen requested\n");                                   //we already have the key (or uid) in the context's data structure
    struct te_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);    //now we must copy it to md context
    unsigned char *keydata;
    if (!data->key_set) {
        printf("Error: key isn't set\n");
        return 0;
    }
    keydata = OPENSSL_malloc(data->key_ln);
    memcpy(keydata, data->key, data->key_ln);
    EVP_PKEY_assign(pkey, NID_hmac_sha1, keydata);
    return 1;
}

static int pkey_gost_mac_signctx_init(EVP_PKEY_CTX *ctx, EVP_MD_CTX *mctx) {
    return 1;
}

static int pkey_gost_mac_signctx(EVP_PKEY_CTX *ctx, unsigned char *sig, size_t *siglen, EVP_MD_CTX *mctx) {
    unsigned int tmpsiglen=*siglen; /* for platforms where sizeof(int)!=sizeof(size_t)*/
    int ret;
    if (!sig) {
        *siglen = 20;   //for sha-1
        return 1;
    }
    ret = EVP_DigestFinal_ex(mctx, sig, &tmpsiglen);
    *siglen = tmpsiglen;
    return ret;
}

static void pkey_gost_mac_cleanup (EVP_PKEY_CTX *ctx) {
    struct te_mac_pmeth_data *data = EVP_PKEY_CTX_get_data(ctx);
    OPENSSL_free(data);
}

static int pkey_gost_mac_copy(EVP_PKEY_CTX *dst, EVP_PKEY_CTX *src) {
    struct te_mac_pmeth_data *dst_data,*src_data;
    if (!pkey_gost_mac_init(dst)) return 0;

    src_data = EVP_PKEY_CTX_get_data(src);
    dst_data = EVP_PKEY_CTX_get_data(dst);
    *dst_data = *src_data;
    return 1;
}

//------------------------------------------------------------------
//Provided digest algorithms

static int test_engine_digest_nids[] = {NID_hmac_sha1, 0};

static int te_digests(ENGINE *e, const EVP_MD **digest, const int **nids, int nid) {
    if (!digest) {
        *nids = test_engine_digest_nids;
        return 1;
    }
    if(nid == NID_hmac_sha1) {
        printf("HMAC-SHA1 requested\n");
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
        || !ENGINE_set_digests(e, te_digests)
        || !ENGINE_set_pkey_meths(e, te_pkey_meths)
        || !ENGINE_set_pkey_asn1_meths(e, te_pkey_asn1_meths) ) {
        printf("Engine init failed\n");
        return 0;
    }

    if (!register_ameth_gost(NID_hmac_sha1, &ameth_HMAC_SHA1, "hmac-sha1", "HMAC-SHA1 MAC")
        || !register_pmeth_gost(NID_hmac_sha1, &pmeth_HMAC_SHA1, 0)) {
        printf("Internal init failed\n");
        return 0;
    }

    if(!ENGINE_register_digests(e)
        || !ENGINE_register_pkey_meths(e)
        || !ENGINE_register_pkey_asn1_meths(e)
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
