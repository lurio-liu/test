#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#include <string.h>

#include "gm0016_api.h"

#define ENGINE_ID   "gm0016"
#define ENGINE_NAME "GM0016 Engine for SM2/SM3/SM4/RAND"

typedef struct {
    void *sm3_ctx;
} GM0016_SM3_CTX;

typedef struct {
    unsigned char key[16];
    unsigned char iv[16];
    int key_len;
    int iv_len;
    int enc;
} GM0016_SM4_CTX;

static int gm0016_rand_bytes(unsigned char *buf, int num) {
    if (num < 0) {
        return 0;
    }
    return gm0016_random(buf, (size_t)num);
}

static int gm0016_rand_status(void) {
    return 1;
}

static RAND_METHOD gm0016_rand_method = {
    NULL,
    gm0016_rand_bytes,
    NULL,
    NULL,
    gm0016_rand_bytes,
    gm0016_rand_status
};

static int gm0016_sm3_init_cb(EVP_MD_CTX *ctx) {
    GM0016_SM3_CTX *mctx = EVP_MD_CTX_md_data(ctx);
    if (mctx == NULL) {
        return 0;
    }
    mctx->sm3_ctx = NULL;
    return gm0016_sm3_init(&mctx->sm3_ctx);
}

static int gm0016_sm3_update_cb(EVP_MD_CTX *ctx, const void *data, size_t count) {
    GM0016_SM3_CTX *mctx = EVP_MD_CTX_md_data(ctx);
    if (mctx == NULL || mctx->sm3_ctx == NULL) {
        return 0;
    }
    return gm0016_sm3_update(mctx->sm3_ctx, (const unsigned char *)data, count);
}

static int gm0016_sm3_final_cb(EVP_MD_CTX *ctx, unsigned char *md) {
    GM0016_SM3_CTX *mctx = EVP_MD_CTX_md_data(ctx);
    unsigned int out_len = 0;
    if (mctx == NULL || mctx->sm3_ctx == NULL) {
        return 0;
    }
    if (!gm0016_sm3_final(mctx->sm3_ctx, md, &out_len)) {
        return 0;
    }
    gm0016_sm3_cleanup(mctx->sm3_ctx);
    mctx->sm3_ctx = NULL;
    return out_len == 32;
}

static int gm0016_sm3_cleanup_fn(EVP_MD_CTX *ctx) {
    GM0016_SM3_CTX *mctx = EVP_MD_CTX_md_data(ctx);
    if (mctx != NULL && mctx->sm3_ctx != NULL) {
        gm0016_sm3_cleanup(mctx->sm3_ctx);
        mctx->sm3_ctx = NULL;
    }
    return 1;
}

static EVP_MD *gm0016_sm3_md = NULL;

static int gm0016_sm4_init(EVP_CIPHER_CTX *ctx, const unsigned char *key,
                           const unsigned char *iv, int enc) {
    GM0016_SM4_CTX *cctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (cctx == NULL) {
        return 0;
    }
    if (key != NULL) {
        memcpy(cctx->key, key, 16);
        cctx->key_len = 16;
    }
    if (iv != NULL) {
        memcpy(cctx->iv, iv, 16);
        cctx->iv_len = 16;
    }
    cctx->enc = enc;
    return 1;
}

static int gm0016_sm4_do_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                const unsigned char *in, size_t inl) {
    GM0016_SM4_CTX *cctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    size_t out_len = inl;
    if (cctx == NULL) {
        return 0;
    }
    return gm0016_sm4_encrypt(cctx->key, (size_t)cctx->key_len,
                              cctx->iv, (size_t)cctx->iv_len,
                              in, inl,
                              out, &out_len,
                              cctx->enc);
}

static int gm0016_sm4_cleanup(EVP_CIPHER_CTX *ctx) {
    GM0016_SM4_CTX *cctx = EVP_CIPHER_CTX_get_cipher_data(ctx);
    if (cctx != NULL) {
        memset(cctx, 0, sizeof(*cctx));
    }
    return 1;
}

static EVP_CIPHER *gm0016_sm4_cipher = NULL;

static int gm0016_sm2_sign_fn(EVP_PKEY_CTX *ctx, unsigned char *sig,
                              size_t *siglen, const unsigned char *tbs,
                              size_t tbslen) {
    (void)ctx;
    return gm0016_sm2_sign(tbs, tbslen, sig, siglen);
}

static int gm0016_sm2_verify_fn(EVP_PKEY_CTX *ctx, const unsigned char *sig,
                                size_t siglen, const unsigned char *tbs,
                                size_t tbslen) {
    (void)ctx;
    return gm0016_sm2_verify(tbs, tbslen, sig, siglen);
}

static int gm0016_sm2_encrypt_fn(EVP_PKEY_CTX *ctx, unsigned char *out,
                                 size_t *outlen, const unsigned char *in,
                                 size_t inlen) {
    (void)ctx;
    return gm0016_sm2_encrypt(in, inlen, out, outlen);
}

static int gm0016_sm2_decrypt_fn(EVP_PKEY_CTX *ctx, unsigned char *out,
                                 size_t *outlen, const unsigned char *in,
                                 size_t inlen) {
    (void)ctx;
    return gm0016_sm2_decrypt(in, inlen, out, outlen);
}

static EVP_PKEY_METHOD *gm0016_sm2_pmeth = NULL;

static int gm0016_engine_destroy(ENGINE *e) {
    (void)e;
    EVP_MD_meth_free(gm0016_sm3_md);
    gm0016_sm3_md = NULL;
    EVP_CIPHER_meth_free(gm0016_sm4_cipher);
    gm0016_sm4_cipher = NULL;
    EVP_PKEY_meth_free(gm0016_sm2_pmeth);
    gm0016_sm2_pmeth = NULL;
    return 1;
}

static int gm0016_register_methods(void) {
    gm0016_sm3_md = EVP_MD_meth_new(NID_sm3, NID_sm3WithRSAEncryption);
    if (gm0016_sm3_md == NULL) return 0;
    if (!EVP_MD_meth_set_result_size(gm0016_sm3_md, 32) ||
        !EVP_MD_meth_set_input_blocksize(gm0016_sm3_md, 64) ||
        !EVP_MD_meth_set_app_datasize(gm0016_sm3_md, sizeof(GM0016_SM3_CTX)) ||
        !EVP_MD_meth_set_flags(gm0016_sm3_md, EVP_MD_FLAG_DIGALGID_ABSENT) ||
        !EVP_MD_meth_set_init(gm0016_sm3_md, gm0016_sm3_init_cb) ||
        !EVP_MD_meth_set_update(gm0016_sm3_md, gm0016_sm3_update_cb) ||
        !EVP_MD_meth_set_final(gm0016_sm3_md, gm0016_sm3_final_cb) ||
        !EVP_MD_meth_set_cleanup(gm0016_sm3_md, gm0016_sm3_cleanup_fn)) {
        return 0;
    }

    gm0016_sm4_cipher = EVP_CIPHER_meth_new(NID_sm4_cbc, 16, 16);
    if (gm0016_sm4_cipher == NULL) return 0;
    if (!EVP_CIPHER_meth_set_iv_length(gm0016_sm4_cipher, 16) ||
        !EVP_CIPHER_meth_set_flags(gm0016_sm4_cipher,
                                   EVP_CIPH_CBC_MODE | EVP_CIPH_FLAG_DEFAULT_ASN1) ||
        !EVP_CIPHER_meth_set_impl_ctx_size(gm0016_sm4_cipher, sizeof(GM0016_SM4_CTX)) ||
        !EVP_CIPHER_meth_set_init(gm0016_sm4_cipher, gm0016_sm4_init) ||
        !EVP_CIPHER_meth_set_do_cipher(gm0016_sm4_cipher, gm0016_sm4_do_cipher) ||
        !EVP_CIPHER_meth_set_cleanup(gm0016_sm4_cipher, gm0016_sm4_cleanup)) {
        return 0;
    }

    gm0016_sm2_pmeth = EVP_PKEY_meth_new(EVP_PKEY_SM2, 0);
    if (gm0016_sm2_pmeth == NULL) return 0;
    EVP_PKEY_meth_set_sign(gm0016_sm2_pmeth, NULL, gm0016_sm2_sign_fn);
    EVP_PKEY_meth_set_verify(gm0016_sm2_pmeth, NULL, gm0016_sm2_verify_fn);
    EVP_PKEY_meth_set_encrypt(gm0016_sm2_pmeth, NULL, gm0016_sm2_encrypt_fn);
    EVP_PKEY_meth_set_decrypt(gm0016_sm2_pmeth, NULL, gm0016_sm2_decrypt_fn);

    return 1;
}

static int gm0016_digests(ENGINE *e, const EVP_MD **digest,
                          const int **nids, int nid) {
    static int digest_nids[] = { NID_sm3, 0 };
    (void)e;
    if (digest == NULL) {
        *nids = digest_nids;
        return 1;
    }
    if (nid == NID_sm3) {
        *digest = gm0016_sm3_md;
        return 1;
    }
    *digest = NULL;
    return 0;
}

static int gm0016_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
                          const int **nids, int nid) {
    static int cipher_nids[] = { NID_sm4_cbc, 0 };
    (void)e;
    if (cipher == NULL) {
        *nids = cipher_nids;
        return 1;
    }
    if (nid == NID_sm4_cbc) {
        *cipher = gm0016_sm4_cipher;
        return 1;
    }
    *cipher = NULL;
    return 0;
}

static int gm0016_pkey_meths(ENGINE *e, EVP_PKEY_METHOD **pmeth,
                             const int **nids, int nid) {
    static int pkey_nids[] = { EVP_PKEY_SM2, 0 };
    (void)e;
    if (pmeth == NULL) {
        *nids = pkey_nids;
        return 1;
    }
    if (nid == EVP_PKEY_SM2) {
        *pmeth = gm0016_sm2_pmeth;
        return 1;
    }
    *pmeth = NULL;
    return 0;
}

static int bind_gm0016(ENGINE *e, const char *id) {
    if (id != NULL && strcmp(id, ENGINE_ID) != 0) {
        return 0;
    }

    if (!gm0016_register_methods()) return 0;

    if (!ENGINE_set_id(e, ENGINE_ID) ||
        !ENGINE_set_name(e, ENGINE_NAME) ||
        !ENGINE_set_destroy_function(e, gm0016_engine_destroy) ||
        !ENGINE_set_digests(e, gm0016_digests) ||
        !ENGINE_set_ciphers(e, gm0016_ciphers) ||
        !ENGINE_set_pkey_meths(e, gm0016_pkey_meths) ||
        !ENGINE_set_RAND(e, &gm0016_rand_method)) {
        return 0;
    }

    return 1;
}

IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_gm0016)
