#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/engine.h>
#include <openssl/hmac.h>
#include "../vhsm_api_prototype/common.h"
#include "../vhsm_api_prototype/mac.h"

#define TEST_ENGINE_ID "test_engine"
#define TEST_ENGINE_NAME "Test Engine"

#define MAX_KEY_LENGTH 64

#define CMD_SO_PATH         ENGINE_CMD_BASE
#define CMD_MODULE_PATH 	(ENGINE_CMD_BASE+1)
#define CMD_PIN             (ENGINE_CMD_BASE+2)

static const ENGINE_CMD_DEFN te_cmd_defns[] = {
    {CMD_SO_PATH, "SO_PATH", "Specifies the path to the engine's shared library", ENGINE_CMD_FLAG_STRING},
    {CMD_MODULE_PATH, "MODULE_PATH", "Specifies the path to the vhsm module shared library", ENGINE_CMD_FLAG_STRING},
    {CMD_PIN, "PIN", "Specifies the pin code", ENGINE_CMD_FLAG_STRING},
    {0, NULL, NULL, 0}
};

static vhsm_session te_vhsm_session;
static vhsm_credentials te_vhsm_credentials;
static vhsm_mac_method te_vhsm_hmac_sha1_method;

//-----------------------------------------------------------------------------
//Internal implemetation of the algorithm

static int te_digest_init(EVP_MD_CTX *ctx);
static int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count);
static int te_digest_final(EVP_MD_CTX *ctx, unsigned char *md);
static int te_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from);
static int te_digest_cleanup(EVP_MD_CTX *ctx);
//static int te_digest_ctrl(EVP_MD_CTX *ctx,int type, int arg, void *ptr);

struct te_hmac_sha1_digest_ctx {
    vhsm_key_id key;
    int key_set;
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
    64,                     //block size in bytes, for SHA1 it should be 64
    sizeof(struct te_hmac_sha1_digest_ctx),
    NULL                    //digest control function
};

//-----------------------------------------------------------------------------
//Backend functions adapter

struct REMOTE_HMAC_CTX {
//    HMAC_CTX hctx;
    int ready;
    int uid_set;
    int skip_update;
};

static struct REMOTE_HMAC_CTX remote_ctx;

#define CREATE_IPAD 1
#define CREATE_OPAD 2
#define UPDATE_HASH 3
#define FINAL_START 4
#define FINAL_END   5

static int init_remote_ctx() {
    if(!remote_ctx.ready) {
        remote_ctx.ready = 1;
        remote_ctx.uid_set = 0;
        remote_ctx.skip_update = 0;
//        HMAC_CTX_init(&remote_ctx.hctx);
    }
    return 1;
}

static int update_remote_ctx(vhsm_key_id *key_id, int phase, const void *data, size_t count) {
    switch(phase) {
    case CREATE_IPAD:
        remote_ctx.uid_set = 1;
        te_vhsm_hmac_sha1_method.key_id = *key_id;
        return vhsm_mac_init(te_vhsm_session, te_vhsm_hmac_sha1_method) == VHSM_RV_OK;
//        return HMAC_Init_ex(&remote_ctx.hctx, "user_123_key", 12, EVP_sha(), NULL);
    case CREATE_OPAD:
        return 1;
    case UPDATE_HASH:
        if(remote_ctx.skip_update) return 1;
        return vhsm_mac_update(te_vhsm_session, (const unsigned char*)data, count) == VHSM_RV_OK;
//        return HMAC_Update(&remote_ctx.hctx, data, count);
    }
    return 0;
}

static int final_remote_ctx(int phase, unsigned char *md) {
    unsigned int len;
    switch(phase) {
    case FINAL_START:
        remote_ctx.skip_update = 1;
        return 1;
    case FINAL_END: {
        remote_ctx.skip_update = 0;
        return vhsm_mac_end(te_vhsm_session, md, &len) == VHSM_RV_OK;
//        int res = HMAC_Final(&remote_ctx.hctx, md, &len);
//        HMAC_CTX_cleanup(&remote_ctx.hctx);
//        return res;
    }
    }
    return 0;
}

//-----------------------------------------------------------------------------
//Internal SHA1 implementation

int te_digest_init(EVP_MD_CTX *ctx) {
    struct te_hmac_sha1_digest_ctx *c = (struct te_hmac_sha1_digest_ctx *)ctx->md_data;
    c->key_set = 0;
    c->final = 0;
    init_remote_ctx();
    return 1;
}

int te_digest_update(EVP_MD_CTX *ctx, const void *data, size_t count) {
    struct te_hmac_sha1_digest_ctx *c = (struct te_hmac_sha1_digest_ctx *)ctx->md_data;
    if(c->key_set == 0) {
        if(count < MAX_KEY_LENGTH) {
            printf("Something went wrong\n");
            return 0;
        }
        if(!remote_ctx.uid_set) {
            for (int i = 0; i < MAX_KEY_LENGTH; i++) c->key.id[i] = 0x36^((const char*)data)[i];
            c->key_set = 1;
            return update_remote_ctx(&c->key, CREATE_IPAD, 0, 0);
        } else {
            for (int i = 0; i < MAX_KEY_LENGTH; i++) c->key.id[i] = 0x5c^((const char*)data)[i];
            c->key_set = 1;
            c->final = 1;
            return update_remote_ctx(&c->key, CREATE_OPAD, 0, 0);
        }
    } else {
        return update_remote_ctx(&c->key, UPDATE_HASH, data, count);
    }
}

int te_digest_final(EVP_MD_CTX *ctx, unsigned char *md) {
    struct te_hmac_sha1_digest_ctx *c = (struct te_hmac_sha1_digest_ctx *)ctx->md_data;
    if(!c->key_set) return 0;
    if(!c->final) return final_remote_ctx(FINAL_START, md);
    else return final_remote_ctx(FINAL_END, md);
}

int te_digest_copy(EVP_MD_CTX *to, const EVP_MD_CTX *from) {
    if (to->md_data && from->md_data) {
        memcpy(to->md_data, from->md_data, sizeof(struct te_hmac_sha1_digest_ctx));
    }
    return 1;
}

int te_digest_cleanup(EVP_MD_CTX *ctx) {
    if (ctx->md_data) {
        struct te_hmac_sha1_digest_ctx *c = (struct te_hmac_sha1_digest_ctx *)ctx->md_data;
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
//Engine commands control (currently unused)

static int test_engine_ctrl(ENGINE * e, int cmd, long i, void *p, void (*f) ()) {
    return 0;
}

//------------------------------------------------------------------
//Engine initialization and finalization

static int test_engine_init(ENGINE *e) {
    printf("Init called\n");
    if(!vhsm_start_session(&te_vhsm_session)
       || !vhsm_login(te_vhsm_session, te_vhsm_credentials)) {
        printf("Unable to start VHSM session\n");
        return 0;
    }

    te_vhsm_hmac_sha1_method.mac_method = VHSM_MAC_HMAC;
    te_vhsm_hmac_sha1_method.method_params = 0;
    return 1;
}

static int test_engine_finish(ENGINE *e) {
    printf("Finish called\n");
    vhsm_logout(te_vhsm_session);
    vhsm_end_session(te_vhsm_session);
    return 1;
}

//------------------------------------------------------------------
//Engine setup

static int bind_helper(ENGINE * e) {
    if (!ENGINE_set_id(e, TEST_ENGINE_ID)
        || !ENGINE_set_name(e, TEST_ENGINE_NAME)
        || !ENGINE_set_init_function(e, test_engine_init)
        || !ENGINE_set_finish_function(e, test_engine_finish)
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

//IMPLEMENT_DYNAMIC_CHECK_FN()
//IMPLEMENT_DYNAMIC_BIND_FN(bind_fn)

extern "C" {
	int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns);
	unsigned long v_check(unsigned long v);
}

unsigned long v_check(unsigned long v) {
	if(v >= OSSL_DYNAMIC_OLDEST) return OSSL_DYNAMIC_VERSION;
	return 0;
}

int bind_engine(ENGINE *e, const char *id, const dynamic_fns *fns) {
	if(ENGINE_get_static_state() == fns->static_state) goto skip_cbs;
	if(!CRYPTO_set_mem_functions(fns->mem_fns.malloc_cb,
		fns->mem_fns.realloc_cb, fns->mem_fns.free_cb))
		return 0;
	CRYPTO_set_locking_callback(fns->lock_fns.lock_locking_cb);
	CRYPTO_set_add_lock_callback(fns->lock_fns.lock_add_lock_cb);
	CRYPTO_set_dynlock_create_callback(fns->lock_fns.dynlock_create_cb);
	CRYPTO_set_dynlock_lock_callback(fns->lock_fns.dynlock_lock_cb);
	CRYPTO_set_dynlock_destroy_callback(fns->lock_fns.dynlock_destroy_cb);
	if(!CRYPTO_set_ex_data_implementation(fns->ex_data_fns))
		return 0;
	if(!ERR_set_implementation(fns->err_fns)) return 0;
	skip_cbs:
	if(!bind_fn(e,id)) return 0;
	return 1;
}
