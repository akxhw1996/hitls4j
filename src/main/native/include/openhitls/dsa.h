#ifndef OPENHITLS_DSA_H
#define OPENHITLS_DSA_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct dsa_ctx_st DSA_CTX;

// Context management
DSA_CTX *DSA_CTX_new(void);
void DSA_CTX_free(DSA_CTX *ctx);

// Key generation and management
int DSA_generate_key_pair(DSA_CTX *ctx, int key_size,
                         unsigned char **pub_key, size_t *pub_key_len,
                         unsigned char **priv_key, size_t *priv_key_len);

int DSA_set_keys(DSA_CTX *ctx,
                 const unsigned char *pub_key, size_t pub_key_len,
                 const unsigned char *priv_key, size_t priv_key_len);

int DSA_set_parameters(DSA_CTX *ctx,
                      const unsigned char *p, size_t p_len,
                      const unsigned char *q, size_t q_len,
                      const unsigned char *g, size_t g_len);

// Signing and verification
int DSA_sign(DSA_CTX *ctx,
             const unsigned char *data, size_t data_len,
             unsigned char **signature, size_t *signature_len,
             int hash_algorithm);

int DSA_verify(DSA_CTX *ctx,
               const unsigned char *data, size_t data_len,
               const unsigned char *signature, size_t signature_len,
               int hash_algorithm);

#ifdef __cplusplus
}
#endif

#endif // OPENHITLS_DSA_H 