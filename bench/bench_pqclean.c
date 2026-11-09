/*
 * ML-DSA-65 from PQClean's portable reference ("clean") implementation: plain
 * C, no assembly, no intrinsics. It is the floor against which the optimised
 * builds are measured, and a third implementation that shares no code with
 * either OpenSSL or liboqs's native path.
 */
#include "api.h"
#include "bench_common.h"

#define NS(x) PQCLEAN_MLDSA65_CLEAN_##x

int main(int argc, char **argv) {
    const char *impl = argc > 1 ? argv[1] : "pqclean-clean";
    static uint8_t pk[NS(CRYPTO_PUBLICKEYBYTES)];
    static uint8_t sk[NS(CRYPTO_SECRETKEYBYTES)];
    static uint8_t sig[NS(CRYPTO_BYTES)];
    size_t siglen = 0;

    if (NS(crypto_sign_keypair)(pk, sk) != 0) return 1;
    TIME_OP(impl, "ML-DSA-65 sign",
            ok_ &= NS(crypto_sign_signature)(sig, &siglen, MSG, MSGLEN, sk) == 0);
    TIME_OP(impl, "ML-DSA-65 verify",
            ok_ &= NS(crypto_sign_verify)(sig, siglen, MSG, MSGLEN, pk) == 0);
    return 0;
}
