#ifndef GM0016_API_H
#define GM0016_API_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * 这些接口由智能密码钥匙 GM0016 厂商 SDK 提供。
 * 返回值约定：1=成功，0=失败。
 */
int gm0016_sm3_init(void **ctx);
int gm0016_sm3_update(void *ctx, const unsigned char *data, size_t data_len);
int gm0016_sm3_final(void *ctx, unsigned char *digest, unsigned int *digest_len);
void gm0016_sm3_cleanup(void *ctx);

int gm0016_sm4_encrypt(const unsigned char *key, size_t key_len,
                       const unsigned char *iv, size_t iv_len,
                       const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t *out_len,
                       int enc);

int gm0016_sm2_sign(const unsigned char *dgst, size_t dgst_len,
                    unsigned char *sig, size_t *sig_len);
int gm0016_sm2_verify(const unsigned char *dgst, size_t dgst_len,
                      const unsigned char *sig, size_t sig_len);
int gm0016_sm2_encrypt(const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t *out_len);
int gm0016_sm2_decrypt(const unsigned char *in, size_t in_len,
                       unsigned char *out, size_t *out_len);

int gm0016_random(unsigned char *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif
