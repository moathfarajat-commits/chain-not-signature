/*
 * ML-DSA-65 through liboqs, on whichever liboqs build this file is linked
 * against. Built twice by run_impls.sh: once with the native aarch64 code
 * paths and once with a generic target and NEON disabled, so the difference
 * between the two runs is vectorisation and nothing else.
 */
#include <oqs/oqs.h>
#include "bench_common.h"

int main(int argc, char **argv) {
    const char *impl = argc > 1 ? argv[1] : "liboqs";
    OQS_init();
    OQS_SIG *s = OQS_SIG_new(OQS_SIG_alg_ml_dsa_65);
    if (!s) { fprintf(stderr, "ML-DSA-65 not enabled in this build\n"); return 1; }
    fprintf(stderr, "%s: liboqs %s, %s\n", impl, OQS_version(), s->alg_version);

    uint8_t *pk = malloc(s->length_public_key);
    uint8_t *sk = malloc(s->length_secret_key);
    uint8_t *sig = malloc(s->length_signature);
    size_t siglen = 0;
    if (OQS_SIG_keypair(s, pk, sk) != OQS_SUCCESS) return 1;

    TIME_OP(impl, "ML-DSA-65 sign",
            ok_ &= OQS_SIG_sign(s, sig, &siglen, MSG, MSGLEN, sk) == OQS_SUCCESS);
    TIME_OP(impl, "ML-DSA-65 verify",
            ok_ &= OQS_SIG_verify(s, MSG, MSGLEN, sig, siglen, pk) == OQS_SUCCESS);

    OQS_SIG_free(s);
    free(pk); free(sk); free(sig);
    OQS_destroy();
    return 0;
}
