#include <string.h>
#include "crypto_backend.h"
#include "plat.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "uECC.h"
#include "sha2.h"

/* ML-DSA entry points. The M0+ build uses PQClean's namespaced names; the M4
 * build links pqm4's three parameter sets with their API renamed at link
 * time (see nucleo/Makefile), so both arrive here under these names. */
#ifdef USE_PQCLEAN_NAMES
#define DECL(N) \
  int PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_keypair(uint8_t *, uint8_t *); \
  int PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_signature(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *); \
  int PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_verify(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
DECL(44) DECL(65) DECL(87)
#define KP(N) PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_keypair
#define SG(N) PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_signature
#define VF(N) PQCLEAN_MLDSA##N##_CLEAN_crypto_sign_verify
#define ML_SIGN(N, sig, sl, m, ml, sk) SG(N)(sig, sl, m, ml, sk)
#define ML_VERIFY(N, sig, sl, m, ml, pk) VF(N)(sig, sl, m, ml, pk)
#define ML_NAME "PQClean ML-DSA clean (portable C)"
#else
#define DECL(N) \
  int mldsa##N##_keypair(uint8_t *, uint8_t *); \
  int mldsa##N##_signature_ctx(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *); \
  int mldsa##N##_verify_ctx(const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *, size_t, const uint8_t *);
DECL(44) DECL(65) DECL(87)
#define KP(N) mldsa##N##_keypair
#define ML_SIGN(N, sig, sl, m, ml, sk) mldsa##N##_signature_ctx(sig, sl, m, ml, NULL, 0, sk)
#define ML_VERIFY(N, sig, sl, m, ml, pk) mldsa##N##_verify_ctx(sig, sl, m, ml, NULL, 0, pk)
#define ML_NAME "pqm4 ML-DSA m4f (Cortex-M4 assembly)"
#endif

/* Boards with a crypto engine (the nRF52840's CryptoCell-310) supply hw_*;
 * c_use_hw switches ES256, Ed25519 and SHA-256 over to it at run time. Key
 * generation stays in software, so both paths use the same keys. */
#ifdef HW_CRYPTO
int hw_supports(int a);
int hw_sign(int a, const uint8_t *sk, const uint8_t *m, size_t mlen, uint8_t *sig);
int hw_verify(int a, const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pk);
void hw_sha256(uint8_t out[32], const uint8_t *in, size_t len);
const char *hw_name(int a);
int c_use_hw;
#define USE_HW(a) (c_use_hw && hw_supports(a))
#else
#define USE_HW(a) 0
#endif

int alg_id(const char *n) {
    if (!strcmp(n, "Ed25519")) return ALG_ED25519;
    if (!strcmp(n, "ES256")) return ALG_ES256;
    if (!strcmp(n, "ML-DSA-44")) return ALG_MLDSA44;
    if (!strcmp(n, "ML-DSA-65")) return ALG_MLDSA65;
    return ALG_MLDSA87;
}

int alg_is_pq(int a) { return a >= ALG_MLDSA44; }

const char *backend_name(int a) {
#ifdef HW_CRYPTO
    if (USE_HW(a)) return hw_name(a);
#endif
    if (a == ALG_ED25519) return "Monocypher 4 (Ed25519)";
    if (a == ALG_ES256) return "micro-ecc (P-256) with SHA-256";
    return ML_NAME;
}

static int uecc_rng(uint8_t *d, unsigned n) {
    while (n) {
        uint32_t r = plat_rand32();
        unsigned k = n < 4 ? n : 4;
        memcpy(d, &r, k);
        d += k; n -= k;
    }
    return 1;
}

int PQCLEAN_randombytes(uint8_t *out, size_t n);
int PQCLEAN_randombytes(uint8_t *out, size_t n) { uecc_rng(out, (unsigned)n); return 0; }
#ifndef USE_PQCLEAN_NAMES
int randombytes(uint8_t *out, size_t n);
int randombytes(uint8_t *out, size_t n) { uecc_rng(out, (unsigned)n); return 0; }
#endif

void c_init(void) { uECC_set_rng(uecc_rng); }

void c_sha256(uint8_t out[32], const uint8_t *in, size_t len) {
#ifdef HW_CRYPTO
    if (c_use_hw) { hw_sha256(out, in, len); return; }
#endif
    sha256(out, in, len);
}

int c_keygen(int a, uint8_t *pk, uint8_t *sk) {
    switch (a) {
    case ALG_ED25519: {
        uint8_t seed[32];
        uecc_rng(seed, 32);
        crypto_ed25519_key_pair(sk, pk, seed);
        return 0;
    }
    case ALG_ES256: return uECC_make_key(pk, sk, uECC_secp256r1()) ? 0 : -1;
    case ALG_MLDSA44: return KP(44)(pk, sk);
    case ALG_MLDSA65: return KP(65)(pk, sk);
    default:          return KP(87)(pk, sk);
    }
}

int c_sign(int a, const uint8_t *sk, const uint8_t *m, size_t mlen,
           uint8_t *sig, size_t *siglen) {
#ifdef HW_CRYPTO
    if (USE_HW(a)) { *siglen = 64; return hw_sign(a, sk, m, mlen, sig); }
#endif
    switch (a) {
    case ALG_ED25519:
        crypto_ed25519_sign(sig, sk, m, mlen);
        *siglen = 64;
        return 0;
    case ALG_ES256: {
        uint8_t h[32];
        c_sha256(h, m, mlen);
        *siglen = 64;
        return uECC_sign(sk, h, 32, sig, uECC_secp256r1()) ? 0 : -1;
    }
    case ALG_MLDSA44: return ML_SIGN(44, sig, siglen, m, mlen, sk);
    case ALG_MLDSA65: return ML_SIGN(65, sig, siglen, m, mlen, sk);
    default:          return ML_SIGN(87, sig, siglen, m, mlen, sk);
    }
}

int c_verify(int a, const uint8_t *sig, size_t siglen,
             const uint8_t *m, size_t mlen, const uint8_t *pk) {
#ifdef HW_CRYPTO
    if (USE_HW(a)) return siglen == 64 && hw_verify(a, sig, m, mlen, pk) == 0 ? 0 : -1;
#endif
    switch (a) {
    case ALG_ED25519:
        return siglen == 64 && crypto_ed25519_check(sig, pk, m, mlen) == 0 ? 0 : -1;
    case ALG_ES256: {
        uint8_t h[32];
        c_sha256(h, m, mlen);
        return siglen == 64 && uECC_verify(pk, h, 32, sig, uECC_secp256r1()) ? 0 : -1;
    }
    default: break;
    }
    /* pqm4's Cortex-M4 code reads the signature and key with word loads;
     * inside a received manifest they can sit at any byte offset, so they
     * are copied to aligned buffers first (a verifier on a byte stream has
     * to do the same). */
    static uint8_t asig[4627] __attribute__((aligned(8)));
    static uint8_t apk[2592] __attribute__((aligned(8)));
    if (siglen > sizeof asig) return -1;
    memcpy(asig, sig, siglen);
    memcpy(apk, pk, a == ALG_MLDSA44 ? 1312 : a == ALG_MLDSA65 ? 1952 : 2592);
    sig = asig;
    pk = apk;
    switch (a) {
    case ALG_MLDSA44: return ML_VERIFY(44, sig, siglen, m, mlen, pk) ? -1 : 0;
    case ALG_MLDSA65: return ML_VERIFY(65, sig, siglen, m, mlen, pk) ? -1 : 0;
    default:          return ML_VERIFY(87, sig, siglen, m, mlen, pk) ? -1 : 0;
    }
}
