/*
 * ML-DSA-65 through the OpenSSL EVP interface, on whatever OpenSSL this file
 * is linked against.
 *
 * The call sequence mirrors what the Python `cryptography` package does for
 * each signature: a fresh digest-sign context, initialised without a digest,
 * one one-shot sign, then freed. So when this harness is linked against a
 * source build and compared with the timing taken through the wheel, the build
 * is the only thing that differs.
 *
 * Signing is timed twice: randomised, which is the default and what the paper
 * reports, and deterministic, which takes the random number generator out of
 * the loop. If the two differ much, the RNG is part of the story.
 */
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/opensslv.h>
#include <openssl/crypto.h>
#include "bench_common.h"

static int sign_once(EVP_PKEY *pkey, int deterministic,
                     unsigned char *sig, size_t *siglen) {
    OSSL_PARAM params[2];
    int det = deterministic;
    params[0] = OSSL_PARAM_construct_int(OSSL_SIGNATURE_PARAM_DETERMINISTIC, &det);
    params[1] = OSSL_PARAM_construct_end();

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestSignInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, params) == 1
          && EVP_DigestSign(ctx, sig, siglen, MSG, MSGLEN) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

static int verify_once(EVP_PKEY *pkey, const unsigned char *sig, size_t siglen) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    int ok = EVP_DigestVerifyInit_ex(ctx, NULL, NULL, NULL, NULL, pkey, NULL) == 1
          && EVP_DigestVerify(ctx, sig, siglen, MSG, MSGLEN) == 1;
    EVP_MD_CTX_free(ctx);
    return ok;
}

int main(int argc, char **argv) {
    const char *impl = argc > 1 ? argv[1] : "openssl";
    fprintf(stderr, "%s: %s\n", impl, OpenSSL_version(OPENSSL_VERSION));
    fprintf(stderr, "%s: %s\n", impl, OpenSSL_version(OPENSSL_CFLAGS));

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, "ML-DSA-65");
    if (!pkey) { fprintf(stderr, "keygen failed\n"); return 1; }

    unsigned char sig[5000];
    size_t siglen = sizeof(sig);

    /* "loop N" signs for N seconds and nothing else, so that a profiler
     * attached to the process sees only the signing path. */
    if (argc > 3 && strcmp(argv[2], "loop") == 0) {
        double end = now_ms() + 1000.0 * atof(argv[3]);
        long count = 0;
        while (now_ms() < end) {
            siglen = sizeof(sig);
            if (!sign_once(pkey, 0, sig, &siglen)) return 1;
            count++;
        }
        fprintf(stderr, "%s: %ld signatures in loop mode\n", impl, count);
        return 0;
    }

    TIME_OP(impl, "ML-DSA-65 sign",
            siglen = sizeof(sig); ok_ &= sign_once(pkey, 0, sig, &siglen));
    TIME_OP(impl, "ML-DSA-65 sign deterministic",
            siglen = sizeof(sig); ok_ &= sign_once(pkey, 1, sig, &siglen));
    TIME_OP(impl, "ML-DSA-65 verify",
            ok_ &= verify_once(pkey, sig, siglen));

    /* SHAKE-256 on a short input, which is what ML-DSA calls hundreds of
     * times per signature. A slow per-call path shows up here even when bulk
     * SHA-3 throughput looks healthy. */
    unsigned char out[136];
    TIME_OP(impl, "SHAKE-256 fetch+short squeeze",
            {
                EVP_MD *md = EVP_MD_fetch(NULL, "SHAKE-256", NULL);
                EVP_MD_CTX *c = EVP_MD_CTX_new();
                ok_ &= EVP_DigestInit_ex(c, md, NULL) == 1
                    && EVP_DigestUpdate(c, MSG, MSGLEN) == 1
                    && EVP_DigestFinalXOF(c, out, sizeof(out)) == 1;
                EVP_MD_CTX_free(c);
                EVP_MD_free(md);
            });

    EVP_PKEY_free(pkey);
    return 0;
}
