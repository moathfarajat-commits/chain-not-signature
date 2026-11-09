/* nRF52840-DK (Cortex-M4F, 64 MHz, 1 MB flash, 256 KB RAM, CryptoCell-310)
 * under the nRF Connect SDK.
 *
 * Software path: the same Monocypher, micro-ecc and PQClean SHA-256 code as
 * the Pico and the NUCLEO. Hardware path: PSA Crypto with the CC3XX driver
 * only (Oberon disabled in prj.conf), so a hardware figure cannot silently
 * come from software. Each hardware sign or verify imports its key, runs,
 * and destroys the key, as a verifier meeting a new certificate would; the
 * import is inside the timed call.
 *
 * Times come from the DWT cycle counter (64 MHz core clock). P0.03 (Arduino
 * A0) is the marker for the PPK2, measured at P22 with SB40 cut. */
#include <stdio.h>
#include <string.h>
#include <zephyr/kernel.h>
#include <ncs_version.h>
#include <zephyr/sys/printk.h>
#include <hal/nrf_gpio.h>
#include <psa/crypto.h>
#include "plat.h"
#include "crypto_backend.h"

void credential_main(void);

#define MARKER_PIN NRF_GPIO_PIN_MAP(0, 3)
#define CPU_HZ 64000000u
#define PAINT 0xA5A5A5A5u

/* ------------------------------------------------------------ platform */

static uint32_t last_cyc;
static uint64_t cyc_hi;

#ifdef CONFIG_BOARD_NRF52_BSIM
#define CYCLES() k_cycle_get_32()           /* BabbleSim: no DWT */
#undef CPU_HZ
#define CPU_HZ sys_clock_hw_cycles_per_sec()
#else
#define CYCLES() DWT->CYCCNT
#endif

void plat_init(void) {
#ifndef CONFIG_BOARD_NRF52_BSIM
    CoreDebug->DEMCR |= CoreDebug_DEMCR_TRCENA_Msk;
    DWT->CYCCNT = 0;
    DWT->CTRL |= DWT_CTRL_CYCCNTENA_Msk;
#endif
    nrf_gpio_cfg_output(MARKER_PIN);
    nrf_gpio_pin_clear(MARKER_PIN);
}

static int rng_failed;
uint32_t plat_rand32(void) {
    uint32_t r = 0;
    if (psa_generate_random((uint8_t *)&r, sizeof r) != PSA_SUCCESS) rng_failed = 1;
    return r;
}

/* 64-bit cycles; the 32-bit counter wraps every 67 s, far longer than any
 * gap between two reads here. */
uint64_t plat_ticks(void) {
    uint32_t c = CYCLES();
    if (c < last_cyc) cyc_hi += 1ull << 32;
    last_cyc = c;
    return cyc_hi | c;
}
uint32_t plat_tick_hz(void) { return CPU_HZ; }
void plat_marker(int on) { nrf_gpio_pin_write(MARKER_PIN, on ? 1 : 0); }
void plat_print(const char *line) { printk("%s\n", line); }
void plat_delay_ms(uint32_t ms) { k_msleep(ms); }

static uintptr_t paint_sp;
static inline uintptr_t current_sp(void) {
    uintptr_t sp;
    __asm volatile ("mov %0, sp" : "=r"(sp));
    return sp;
}
#ifdef CONFIG_BOARD_NRF52_BSIM
void plat_stack_paint(void) {}             /* threads run on host stacks */
size_t plat_stack_used(void) { return 0; }
#else
void plat_stack_paint(void) {
    paint_sp = current_sp();
    uint32_t *lo = (uint32_t *)k_current_get()->stack_info.start;
    for (uint32_t *w = lo; w < (uint32_t *)(paint_sp - 64); w++) *w = PAINT;
}
size_t plat_stack_used(void) {
    uint32_t *w = (uint32_t *)k_current_get()->stack_info.start;
    while (*w == PAINT) w++;
    return (size_t)(paint_sp - (uintptr_t)w);
}
#endif

static int ed25519_hw;      /* probed at start: does CC3XX take Ed25519? */
static int sha_check;       /* engine SHA-256 of flash and RAM data equals software's */
/* First PSA status seen at each step, per scheme (0 ES256, 1 Ed25519),
 * reported in env so a refusal by the engine can be read off the log. */
static int st_imp_priv[2], st_sign[2], st_imp_pub[2], st_ver[2];

const char *plat_env_json(void) {
    static char env[400];
    snprintf(env, sizeof env,
             "\"board\":\"nRF52840-DK\",\"chip\":\"nRF52840\",\"core\":\"Cortex-M4F\","
             "\"clk_sys_hz\":%u,\"ncs\":\"%s\",\"compiler\":\"%s\","
             "\"timer\":\"DWT cycle counter\",\"hw_engine\":\"CryptoCell-310 via PSA (CC3XX driver)\","
             "\"hw_ed25519\":%s,\"hw_includes_key_import\":true,"
             "\"psa_es256\":[%d,%d,%d,%d],\"psa_ed25519\":[%d,%d,%d,%d],"
             "\"hw_sha256_matches_sw\":%s",
             CPU_HZ, NCS_VERSION_STRING, __VERSION__, ed25519_hw ? "true" : "false",
             st_imp_priv[0], st_sign[0], st_imp_pub[0], st_ver[0],
             st_imp_priv[1], st_sign[1], st_imp_pub[1], st_ver[1],
             sha_check ? "true" : "false");
    return env;
}

/* ------------------------------------------------------- CryptoCell path */

static psa_status_t import_key(int a, int priv, const uint8_t *k, psa_key_id_t *id) {
    psa_key_attributes_t at = PSA_KEY_ATTRIBUTES_INIT;
    uint8_t pub[65];
    const uint8_t *data = k;
    size_t len;
    if (a == ALG_ES256) {
        psa_set_key_type(&at, priv ? PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1)
                                   : PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_SECP_R1));
        psa_set_key_bits(&at, 256);
        psa_set_key_algorithm(&at, PSA_ALG_ECDSA(PSA_ALG_SHA_256));
        if (priv) {
            len = 32;
        } else {
            pub[0] = 0x04;                  /* micro-ecc keeps X||Y */
            memcpy(pub + 1, k, 64);
            data = pub;
            len = 65;
        }
    } else {
        psa_set_key_type(&at, priv ? PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_TWISTED_EDWARDS)
                                   : PSA_KEY_TYPE_ECC_PUBLIC_KEY(PSA_ECC_FAMILY_TWISTED_EDWARDS));
        psa_set_key_bits(&at, 255);
        psa_set_key_algorithm(&at, PSA_ALG_PURE_EDDSA);
        len = 32;                           /* Monocypher sk = seed || pk */
    }
    psa_set_key_usage_flags(&at, priv ? (PSA_KEY_USAGE_SIGN_MESSAGE | PSA_KEY_USAGE_SIGN_HASH)
                                      : (PSA_KEY_USAGE_VERIFY_MESSAGE | PSA_KEY_USAGE_VERIFY_HASH));
    return psa_import_key(&at, data, len, id);
}

static psa_algorithm_t psa_alg(int a) {
    return a == ALG_ES256 ? PSA_ALG_ECDSA(PSA_ALG_SHA_256) : PSA_ALG_PURE_EDDSA;
}

int hw_supports(int a) { return a == ALG_ES256 || (a == ALG_ED25519 && ed25519_hw); }

const char *hw_name(int a) {
    return a == ALG_ES256 ? "CryptoCell-310 ECDSA P-256 + SHA-256 (PSA)"
                          : "CryptoCell-310 Ed25519 (PSA)";
}

#define NOTE(arr, a, st) do { if ((st) != PSA_SUCCESS && !arr[(a) == ALG_ED25519]) arr[(a) == ALG_ED25519] = (st); } while (0)

/* The CryptoCell-310 reads its input by DMA, which reaches RAM only, not
 * flash. Anything in flash (certificates in the trust store, constant
 * manifests) is copied through a RAM bounce buffer first; a verifier on this
 * chip has to do the same, so the copy is inside the timed call. */
#define RAM_START 0x20000000u
#define RAM_END   0x20040000u
static uint8_t bounce[2048] __aligned(4);
static int in_ram(const void *p, size_t n) {
    uintptr_t a = (uintptr_t)p;
    return a >= RAM_START && a + n <= RAM_END;
}

static psa_status_t hw_hash(uint8_t out[32], const uint8_t *in, size_t len) {
    psa_hash_operation_t op = PSA_HASH_OPERATION_INIT;
    size_t n;
    psa_status_t st = psa_hash_setup(&op, PSA_ALG_SHA_256);
    if (st == PSA_SUCCESS && in_ram(in, len)) {
        st = psa_hash_update(&op, in, len);
    } else {
        while (st == PSA_SUCCESS && len) {
            size_t k = len < sizeof bounce ? len : sizeof bounce;
            memcpy(bounce, in, k);
            st = psa_hash_update(&op, bounce, k);
            in += k;
            len -= k;
        }
    }
    if (st == PSA_SUCCESS) st = psa_hash_finish(&op, out, 32, &n);
    else psa_hash_abort(&op);
    return st;
}

static int hw_sha_failed;
void hw_sha256(uint8_t out[32], const uint8_t *in, size_t len) {
    if (hw_hash(out, in, len) != PSA_SUCCESS) {
        memset(out, 0, 32);
        hw_sha_failed = 1;
    }
}

/* ES256: SHA-256 on the engine, then ECDSA on the digest. Ed25519 (pure
 * EdDSA) needs the whole message, so it goes through the bounce buffer. */
static const uint8_t *msg_in_ram(const uint8_t *m, size_t mlen) {
    if (in_ram(m, mlen)) return m;
    if (mlen > sizeof bounce) return NULL;
    memcpy(bounce, m, mlen);
    return bounce;
}

int hw_sign(int a, const uint8_t *sk, const uint8_t *m, size_t mlen, uint8_t *sig) {
    psa_key_id_t id;
    size_t n = 0;
    uint8_t h[32];
    psa_status_t st = import_key(a, 1, sk, &id);
    NOTE(st_imp_priv, a, st);
    if (st != PSA_SUCCESS) return -1;
    if (a == ALG_ES256) {
        st = hw_hash(h, m, mlen);
        if (st == PSA_SUCCESS) st = psa_sign_hash(id, psa_alg(a), h, 32, sig, 64, &n);
    } else {
        const uint8_t *mm = msg_in_ram(m, mlen);
        st = mm ? psa_sign_message(id, psa_alg(a), mm, mlen, sig, 64, &n) : PSA_ERROR_BUFFER_TOO_SMALL;
    }
    NOTE(st_sign, a, st);
    psa_destroy_key(id);
    return st == PSA_SUCCESS && n == 64 ? 0 : -1;
}

int hw_verify(int a, const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pk) {
    psa_key_id_t id;
    uint8_t h[32], s64[64];
    memcpy(s64, sig, 64);                    /* the signature may sit in flash */
    psa_status_t st = import_key(a, 0, pk, &id);
    NOTE(st_imp_pub, a, st);
    if (st != PSA_SUCCESS) return -1;
    if (a == ALG_ES256) {
        st = hw_hash(h, m, mlen);
        if (st == PSA_SUCCESS) st = psa_verify_hash(id, psa_alg(a), h, 32, s64, 64);
    } else {
        const uint8_t *mm = msg_in_ram(m, mlen);
        st = mm ? psa_verify_message(id, psa_alg(a), mm, mlen, s64, 64) : PSA_ERROR_BUFFER_TOO_SMALL;
    }
    /* A bad signature is an expected answer, not an engine fault */
    if (st != PSA_ERROR_INVALID_SIGNATURE) NOTE(st_ver, a, st);
    psa_destroy_key(id);
    return st == PSA_SUCCESS ? 0 : -1;
}

/* Sign and verify once with a fixed Ed25519 key on the engine; if either is
 * refused, Ed25519 stays software-only and env says so. */
static void probe_ed25519(void) {
    uint8_t sk[64], pk[32], sig[64];
    const uint8_t msg[3] = {'a', 'b', 'c'};
    int save = c_use_hw;
    c_use_hw = 0;
    c_keygen(ALG_ED25519, pk, sk);
    ed25519_hw = 1;
    ed25519_hw = hw_sign(ALG_ED25519, sk, msg, 3, sig) == 0 &&
                 hw_verify(ALG_ED25519, sig, msg, 3, pk) == 0;
    /* and it must agree with Monocypher's verifier */
    if (ed25519_hw) ed25519_hw = c_verify(ALG_ED25519, sig, 64, msg, 3, pk) == 0;
    /* SHA-256 on the engine must agree with software, for data in flash
     * (this function's own code) and in RAM */
    {
        uint8_t h1[32], h2[32], h3[32], h4[32];
        static uint8_t ram_blk[3000];
        const uint8_t *fl = (const uint8_t *)probe_ed25519;
        for (size_t i = 0; i < sizeof ram_blk; i++) ram_blk[i] = (uint8_t)(i * 7);
        hw_sha_failed = 0;
        hw_sha256(h1, fl, 3000);
        hw_sha256(h3, ram_blk, sizeof ram_blk);
        c_use_hw = 0;
        c_sha256(h2, fl, 3000);
        c_sha256(h4, ram_blk, sizeof ram_blk);
        sha_check = !hw_sha_failed && !memcmp(h1, h2, 32) && !memcmp(h3, h4, 32);
    }
    /* ES256 the same way, only to fill in the status codes */
    uint8_t esk[32], epk[64];
    c_keygen(ALG_ES256, epk, esk);
    if (hw_sign(ALG_ES256, esk, msg, 3, sig) == 0) {
        c_use_hw = 0;
        hw_verify(ALG_ES256, sig, msg, 3, epk);
    }
    c_use_hw = save;
}

int main(void) {
    plat_init();
    if (psa_crypto_init() != PSA_SUCCESS) {
        printk("{\"op\":\"error\",\"what\":\"psa_crypto_init\"}\n");
        return 0;
    }
    c_init();
    uint32_t a = plat_rand32(), b = plat_rand32();
    if (rng_failed || a == b) {
        printk("{\"op\":\"error\",\"what\":\"psa_generate_random\"}\n");
        return 0;
    }
    probe_ed25519();
#ifndef ENERGY
    k_msleep(3000);         /* time to start the capture script */
#endif
    credential_main();
    return 0;
}
