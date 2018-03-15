#include <errno.h>

#include "crypto_kdf_ed25519.h"
#include "private/common.h"
#include "utils.h"
#include "crypto_scalarmult_ed25519.h"
#include "crypto_auth_hmacsha512.h"
#include "crypto_auth_hmacsha256.h"
#include "private/ed25519_ref10.h"
#include "crypto_core_ed25519.h"
#include "randombytes.h"

int _pre_child_calc(unsigned char *sub_a,
                     unsigned char *sub_chain_code,
                     unsigned char *z,
                     uint32_t subkey_id,
                     const unsigned char *a, const unsigned char *sign_seed,
                     const unsigned char *chain_code, const unsigned char *pub_key)
{
    unsigned char *data;
    uint8_t data_size;
    uint8_t kpre, cpre;
    uint32_t le_subkey_id = htole32(subkey_id);

    if (subkey_id & (1u << 31))
    {
        if (a == NULL || sign_seed == NULL)
            return 1;

        data = (unsigned char *)sodium_malloc(data_size = 1 + 64 + 4);
        memcpy(data+1, a, 32);
        memcpy(data+33, sign_seed, 32);
        memcpy(data+65, &le_subkey_id, 4);
        kpre = 0;
        cpre = 1;
    }
    else
    {
        data = (unsigned char *)sodium_malloc(data_size = 1 + 32 + 4);
        memcpy(data+1, pub_key, 32);
        memcpy(data+33, &le_subkey_id, 4);
        kpre = 2;
        cpre = 3;
    }
    
    data[0] = cpre;
    crypto_auth_hmacsha512(z, data, data_size, chain_code);
    memcpy(sub_chain_code, z + 32, 32);
    
    data[0] = kpre;
    crypto_auth_hmacsha512(z, data, data_size, chain_code);
    sodium_free(data);
    memset(sub_a + 28, 0, 4);
    memcpy(sub_a, z, 28);
    
    // *8
    for (int i = 27; i >= 0; i--)
    {
        sub_a[i+1] |= sub_a[i] >> 5;
        sub_a[i] <<= 3;
    }
}

void _clamp(uint8_t *k)
{
    k[0]  &= 0b11111000; // F8, 248
    k[31] &= 0b01111111; // 7F, 127
    k[31] |= 0b01000000; // 40, 64
}

int _crypto_scalarmult_ed25519_base_no_clamp(unsigned char *q,
                               const unsigned char *n)
{
    unsigned char *t = q;
    ge25519_p3     Q;
    unsigned int   i;

    for (i = 0; i < 32; ++i) {
        t[i] = n[i];
    }
    ge25519_scalarmult_base(&Q, t);
    ge25519_p3_tobytes(q, &Q);
    if (sodium_is_zero(n, 32) != 0) {
        return -1;
    }
    return 0;
}

int crypto_kdf_ed25519_generate_key(unsigned char *a, unsigned char *sign_seed,
                                    unsigned char *chain_code, unsigned char *pub_key, 
                                    unsigned char *secret)
{
    uint8_t k[64];
    uint8_t *s = secret ? secret : (uint8_t *)sodium_malloc(32);
    uint8_t s2[33];

    while (1)
    {
        if (!secret)
            randombytes_buf(s, 32);

        crypto_hash_sha512(k, s, 32);

        if (k[31] & 0x20)
        {
            if (secret)
                return -1;
        }
        else
            break;
    }

    memcpy(a, k, 32);
    _clamp(a);

    s2[0] = 1;
    memcpy(s2 + 1, s, 32);
    crypto_hash_sha256(chain_code, s2, 33);

    crypto_scalarmult_ed25519_base(pub_key, a);

    memcpy(sign_seed, k + 32, 32);

    if (!secret)
        sodium_free(s);
}

int crypto_kdf_ed25519_derive_from_key(unsigned char *sub_a, unsigned char *sub_sign_seed,
                                       unsigned char *sub_chain_code, unsigned char *sub_pub_key,
                                       uint32_t subkey_id,
                                       const unsigned char *a, const unsigned char *sign_seed,
                                       const unsigned char *chain_code, const unsigned char *pub_key)
{
    unsigned char z[64];

    _pre_child_calc(sub_a, sub_chain_code, z, subkey_id, a, sign_seed, chain_code, pub_key);
    
    sodium_add(sub_a, a, 32);
    
    memcpy(sub_sign_seed, sign_seed, 32);
    sodium_add(sub_sign_seed, z + 32, 32);
    
    crypto_scalarmult_ed25519_base(sub_pub_key, sub_a);

    return 0;
}

int crypto_kdf_ed25519_derive_from_key_public(unsigned char *sub_chain_code, unsigned char *sub_pub_key,
                                              uint32_t subkey_id,
                                              const unsigned char *chain_code, const unsigned char *pub_key)
{
    unsigned char z[64];
    unsigned char addend[32];

    _pre_child_calc(addend, sub_chain_code, z, subkey_id, NULL, NULL, chain_code, pub_key);
    
    _crypto_scalarmult_ed25519_base_no_clamp(addend, addend);
    crypto_core_ed25519_add(sub_pub_key, addend, pub_key);

    return 0;
}
