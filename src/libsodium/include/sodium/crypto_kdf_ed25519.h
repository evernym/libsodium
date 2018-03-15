#ifndef crypto_kdf_ed25519_H
#define crypto_kdf_ed25519_H

#include <stddef.h>
#include <stdint.h>

#include "crypto_kdf_ed25519.h"
#include "export.h"

#ifdef __cplusplus
# ifdef __GNUC__
#  pragma GCC diagnostic ignored "-Wlong-long"
# endif
extern "C" {
#endif

SODIUM_EXPORT
int crypto_kdf_ed25519_generate_key(unsigned char *a, unsigned char *sign_seed,
                                    unsigned char *chain_code, unsigned char *pub_key, 
                                    unsigned char *secret);

SODIUM_EXPORT
int crypto_kdf_ed25519_derive_from_key(unsigned char *sub_a, unsigned char *sub_sign_seed,
                                       unsigned char *sub_chain_code, unsigned char *sub_pub_key,
                                       uint32_t subkey_id,
                                       const unsigned char *a, const unsigned char *sign_seed,
                                       const unsigned char *chain_code, const unsigned char *pub_key);

SODIUM_EXPORT
int crypto_kdf_ed25519_derive_from_key_public(unsigned char *sub_chain_code, unsigned char *sub_pub_key,
                                              uint32_t subkey_id,
                                              const unsigned char *chain_code, const unsigned char *pub_key);

#ifdef __cplusplus
}
#endif

#endif
