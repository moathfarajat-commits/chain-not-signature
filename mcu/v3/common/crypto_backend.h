/* Signature schemes behind one interface. Implemented per board in
 * crypto_backend.c with the board's ML-DSA build (PQClean portable C on the
 * Cortex-M0+, pqm4's Cortex-M4 code on the M4) and the same Ed25519
 * (Monocypher) and ES256 (micro-ecc, SHA-256) everywhere. */
#ifndef CRYPTO_BACKEND_H
#define CRYPTO_BACKEND_H
#include <stdint.h>
#include <stddef.h>

enum { ALG_ED25519, ALG_ES256, ALG_MLDSA44, ALG_MLDSA65, ALG_MLDSA87 };

int alg_id(const char *name);
int alg_is_pq(int a);
const char *backend_name(int a);

int c_keygen(int a, uint8_t *pk, uint8_t *sk);
int c_sign(int a, const uint8_t *sk, const uint8_t *m, size_t mlen,
           uint8_t *sig, size_t *siglen);
/* pk: 32 B Ed25519, 64 B X||Y P-256, FIPS 204 encoding for ML-DSA.
 * sig: 64 B r||s for ES256. Returns 0 if valid. */
int c_verify(int a, const uint8_t *sig, size_t siglen,
             const uint8_t *m, size_t mlen, const uint8_t *pk);
void c_sha256(uint8_t out[32], const uint8_t *in, size_t len);
void c_init(void);
#ifdef HW_CRYPTO
extern int c_use_hw;   /* 1: classical schemes and SHA-256 on the crypto engine */
int hw_supports(int a);
#endif

#endif
