/*
 * Line A, E9/E10: content-credential signing and verification on a
 * microcontroller. Board-independent; plat.h and crypto_backend.h supply the
 * board.
 *
 * Timing build (default). For each algorithm: key generation, signing and
 * verification of the COSE Sig_structure of a real manifest; validation of a
 * three-certificate chain; and whole-manifest verification in the paper's
 * three carriage forms:
 *   full    the chain arrives in the manifest (x5chain of three)
 *   leaf    only the leaf arrives; intermediate and root are in the trust store
 *   thumb   only an x5t thumbprint arrives; the leaf is in the trust store too
 * Each manifest is first copied into a receive buffer in RAM, as one arriving
 * over a link would be, and the Sig_structure is rebuilt in a second buffer:
 * the RAM figure reported is those two buffers plus the peak stack.
 *
 * Energy build (-DENERGY). The same operations, each repeated a fixed number
 * of times inside a marker-pin window, separated by idle gaps; the schedule
 * (schedule.h, generated from schedule.json) tells the PPK2 runner which
 * window is which. No serial output is needed, so the Pico can run from the
 * PPK2's supply alone.
 */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "plat.h"
#include "crypto_backend.h"
#include "vectors.h"

/* ---------------------------------------------------------------- buffers */

#define RX_MAX (28 * 1024)
static uint8_t g_rx[RX_MAX] __attribute__((aligned(8)));        /* the manifest as received */
static size_t g_rx_len;
static uint8_t g_msg[RX_MAX] __attribute__((aligned(8)));       /* the Sig_structure rebuilt from it */
static size_t g_msg_len;
static uint8_t g_pk[2592], g_sk[4896], g_sig[4627 + 16];
static size_t g_siglen;

static const vec_t *g_vec;
static int g_alg;
static uint8_t g_thumb[32];         /* trust store index: SHA-256 of the leaf */

static char line[512];
#define OUT(...) do { snprintf(line, sizeof line, __VA_ARGS__); plat_print(line); } while (0)

/* -------------------------------------------------------------------- DER */

typedef struct { const uint8_t *p; size_t n; } span_t;

static int der_next(const uint8_t **pp, const uint8_t *end, uint8_t *tag,
                    span_t *val, span_t *whole) {
    const uint8_t *p = *pp;
    if (end - p < 2) return -1;
    const uint8_t *start = p;
    *tag = *p++;
    size_t len = *p++;
    if (len & 0x80) {
        int k = len & 0x7f;
        if (k < 1 || k > 3 || end - p < k) return -1;
        len = 0;
        while (k--) len = (len << 8) | *p++;
    }
    if ((size_t)(end - p) < len) return -1;
    val->p = p; val->n = len;
    if (whole) { whole->p = start; whole->n = (size_t)(p - start) + len; }
    *pp = p + len;
    return 0;
}

typedef struct { span_t tbs, sig, pk; } cert_t;

static int x509_parse(span_t der, cert_t *c) {
    const uint8_t *p = der.p, *end = der.p + der.n;
    uint8_t tag;
    span_t v, w;
    if (der_next(&p, end, &tag, &v, NULL) || tag != 0x30) return -1;
    p = v.p; end = v.p + v.n;
    if (der_next(&p, end, &tag, &v, &c->tbs) || tag != 0x30) return -1;
    span_t tbs = v;
    if (der_next(&p, end, &tag, &v, NULL) || tag != 0x30) return -1;
    if (der_next(&p, end, &tag, &v, NULL) || tag != 0x03 || v.n < 1) return -1;
    c->sig.p = v.p + 1; c->sig.n = v.n - 1;
    p = tbs.p; end = tbs.p + tbs.n;
    if (der_next(&p, end, &tag, &v, &w)) return -1;
    if (tag == 0xA0 && der_next(&p, end, &tag, &v, &w)) return -1;
    for (int i = 0; i < 4; i++)
        if (der_next(&p, end, &tag, &v, NULL)) return -1;
    if (der_next(&p, end, &tag, &v, NULL) || tag != 0x30) return -1;
    const uint8_t *q = v.p, *qe = v.p + v.n;
    if (der_next(&q, qe, &tag, &v, NULL) || tag != 0x30) return -1;
    if (der_next(&q, qe, &tag, &v, NULL) || tag != 0x03 || v.n < 1) return -1;
    c->pk.p = v.p + 1; c->pk.n = v.n - 1;
    return 0;
}

static int ecdsa_der_to_raw(span_t der, uint8_t out[64]) {
    const uint8_t *p = der.p, *end = der.p + der.n;
    uint8_t tag;
    span_t v;
    if (der_next(&p, end, &tag, &v, NULL) || tag != 0x30) return -1;
    p = v.p; end = v.p + v.n;
    for (int i = 0; i < 2; i++) {
        if (der_next(&p, end, &tag, &v, NULL) || tag != 0x02) return -1;
        while (v.n > 32 && v.p[0] == 0) { v.p++; v.n--; }
        if (v.n > 32) return -1;
        memset(out + 32 * i, 0, 32 - v.n);
        memcpy(out + 32 * i + 32 - v.n, v.p, v.n);
    }
    return 0;
}

static const uint8_t *raw_pk(int a, span_t pk) {
    if (a == ALG_ES256 && pk.n == 65 && pk.p[0] == 0x04) return pk.p + 1;
    return pk.p;
}

static int cert_verify(int a, const cert_t *child, const cert_t *parent) {
    const uint8_t *pk = raw_pk(a, parent->pk);
    if (a == ALG_ES256) {
        uint8_t rs[64];
        if (ecdsa_der_to_raw(child->sig, rs)) return -1;
        return c_verify(a, rs, 64, child->tbs.p, child->tbs.n, pk);
    }
    return c_verify(a, child->sig.p, child->sig.n, child->tbs.p, child->tbs.n, pk);
}

/* ------------------------------------------------------------------- CBOR */

static int cbor_head(const uint8_t **pp, const uint8_t *end, int *major, uint64_t *val) {
    const uint8_t *p = *pp;
    if (p >= end) return -1;
    uint8_t ib = *p++;
    *major = ib >> 5;
    int ai = ib & 31;
    uint64_t v;
    if (ai < 24) v = (uint64_t)ai;
    else {
        int k = ai == 24 ? 1 : ai == 25 ? 2 : ai == 26 ? 4 : ai == 27 ? 8 : -1;
        if (k < 0 || end - p < k) return -1;
        v = 0;
        while (k--) v = (v << 8) | *p++;
    }
    *val = v;
    *pp = p;
    return 0;
}

static size_t cbor_put_head(uint8_t *out, int major, uint64_t v) {
    uint8_t m = (uint8_t)(major << 5);
    if (v < 24) { out[0] = m | (uint8_t)v; return 1; }
    if (v < 0x100) { out[0] = m | 24; out[1] = (uint8_t)v; return 2; }
    if (v < 0x10000) { out[0] = m | 25; out[1] = (uint8_t)(v >> 8); out[2] = (uint8_t)v; return 3; }
    out[0] = m | 26;
    out[1] = (uint8_t)(v >> 24); out[2] = (uint8_t)(v >> 16);
    out[3] = (uint8_t)(v >> 8); out[4] = (uint8_t)v;
    return 5;
}

typedef struct {
    span_t prot, sig;
    span_t certs[3];
    int ncerts;
    int has_x5t;
    span_t x5t;
} cose_t;

static int cose_decode(const uint8_t *b, size_t n, cose_t *c) {
    const uint8_t *p = b, *end = b + n;
    int mj; uint64_t v;
    memset(c, 0, sizeof *c);
    if (cbor_head(&p, end, &mj, &v) || mj != 6 || v != 18) return -1;
    if (cbor_head(&p, end, &mj, &v) || mj != 4 || v != 4) return -1;
    if (cbor_head(&p, end, &mj, &v) || mj != 2 || (uint64_t)(end - p) < v) return -1;
    c->prot.p = p; c->prot.n = (size_t)v; p += v;
    if (cbor_head(&p, end, &mj, &v) || mj != 5 || v != 0) return -1;
    if (p >= end || *p++ != 0xf6) return -1;
    if (cbor_head(&p, end, &mj, &v) || mj != 2 || (uint64_t)(end - p) < v) return -1;
    c->sig.p = p; c->sig.n = (size_t)v;

    p = c->prot.p; end = p + c->prot.n;
    uint64_t npairs;
    if (cbor_head(&p, end, &mj, &npairs) || mj != 5) return -1;
    for (uint64_t i = 0; i < npairs; i++) {
        uint64_t key;
        if (cbor_head(&p, end, &mj, &key) || mj != 0) return -1;
        if (key == 1) {
            if (cbor_head(&p, end, &mj, &v)) return -1;
        } else if (key == 33) {                     /* x5chain: bstr or [bstr] */
            if (cbor_head(&p, end, &mj, &v)) return -1;
            if (mj == 2) {
                if ((uint64_t)(end - p) < v) return -1;
                c->certs[0].p = p; c->certs[0].n = (size_t)v; p += v;
                c->ncerts = 1;
            } else if (mj == 4 && v <= 3) {
                uint64_t k = v;
                for (uint64_t j = 0; j < k; j++) {
                    if (cbor_head(&p, end, &mj, &v) || mj != 2 || (uint64_t)(end - p) < v) return -1;
                    c->certs[j].p = p; c->certs[j].n = (size_t)v; p += v;
                }
                c->ncerts = (int)k;
            } else return -1;
        } else if (key == 34) {                     /* x5t: [hash alg, hash] */
            if (cbor_head(&p, end, &mj, &v) || mj != 4 || v != 2) return -1;
            if (cbor_head(&p, end, &mj, &v)) return -1;  /* -16, SHA-256 */
            if (cbor_head(&p, end, &mj, &v) || mj != 2 || v != 32 || end - p < 32) return -1;
            c->x5t.p = p; c->x5t.n = 32; p += 32;
            c->has_x5t = 1;
        } else return -1;
    }
    return 0;
}

static size_t sig_structure(uint8_t *out, span_t prot, const uint8_t *payload, size_t plen) {
    size_t o = 0;
    out[o++] = 0x84;
    out[o++] = 0x6a;
    memcpy(out + o, "Signature1", 10); o += 10;
    o += cbor_put_head(out + o, 2, prot.n);
    memcpy(out + o, prot.p, prot.n); o += prot.n;
    out[o++] = 0x40;
    o += cbor_put_head(out + o, 2, plen);
    memcpy(out + o, payload, plen); o += plen;
    return o;
}

/* ------------------------------------------------------------- operations */

static int receive(const uint8_t *b, size_t n) {
    if (n > RX_MAX) return -1;
    memcpy(g_rx, b, n);
    g_rx_len = n;
    return 0;
}

static span_t sp(const uint8_t *p, size_t n) { span_t s = { p, n }; return s; }

/* Verify the manifest in g_rx. form: 0 full, 1 leaf, 2 thumb, 3 chain. */
static int verify_received(int form) {
    cose_t c;
    cert_t leaf, mid, root;
    if (cose_decode(g_rx, g_rx_len, &c)) return -1;
    span_t lc, mc, rc;
    if (form == 0) {
        if (c.ncerts != 3) return -1;
        lc = c.certs[0]; mc = c.certs[1]; rc = c.certs[2];
    } else if (form == 3) {
        if (c.ncerts != 2) return -1;
        lc = c.certs[0]; mc = c.certs[1];
        rc = sp(g_vec->ts_root, g_vec->ts_root_len);
    } else if (form == 1) {
        if (c.ncerts != 1) return -1;
        lc = c.certs[0];
        mc = sp(g_vec->ts_mid, g_vec->ts_mid_len);
        rc = sp(g_vec->ts_root, g_vec->ts_root_len);
    } else {
        if (!c.has_x5t || memcmp(c.x5t.p, g_thumb, 32)) return -1;
        lc = sp(g_vec->ts_leaf, g_vec->ts_leaf_len);
        mc = sp(g_vec->ts_mid, g_vec->ts_mid_len);
        rc = sp(g_vec->ts_root, g_vec->ts_root_len);
    }
    if (x509_parse(lc, &leaf) || x509_parse(mc, &mid) || x509_parse(rc, &root)) return -1;
    /* The anchor's self-signature is not checked: it is trusted by being in
     * the trust store, as in the rest of the paper. */
    if (cert_verify(g_alg, &leaf, &mid)) return -2;
    if (cert_verify(g_alg, &mid, &root)) return -3;
    g_msg_len = sig_structure(g_msg, c.prot, CLAIM, sizeof CLAIM);
    return c_verify(g_alg, c.sig.p, c.sig.n, g_msg, g_msg_len, raw_pk(g_alg, leaf.pk)) ? -4 : 0;
}

static int op_keygen(void) { return c_keygen(g_alg, g_pk, g_sk); }
static int op_sign(void) { return c_sign(g_alg, g_sk, g_msg, g_msg_len, g_sig, &g_siglen); }
static int op_verify(void) { return c_verify(g_alg, g_sig, g_siglen, g_msg, g_msg_len, g_pk); }
static int op_chain(void) {
    cose_t c;
    cert_t l, m, r;
    if (cose_decode(g_vec->full, g_vec->full_len, &c) || c.ncerts != 3) return -1;
    if (x509_parse(c.certs[0], &l) || x509_parse(c.certs[1], &m) || x509_parse(c.certs[2], &r)) return -1;
    if (cert_verify(g_alg, &l, &m)) return -2;
    return cert_verify(g_alg, &m, &r) ? -3 : 0;
}
static int op_full(void)  { return receive(g_vec->full, g_vec->full_len) || verify_received(0); }
static int op_leaf(void)  { return receive(g_vec->leaf, g_vec->leaf_len) || verify_received(1); }
static int op_chainf(void) { return receive(g_vec->chain, g_vec->chain_len) || verify_received(3); }
static int op_thumb(void) { return receive(g_vec->thumb, g_vec->thumb_len) || verify_received(2); }

static uint8_t hbuf[8 * 1024];
static int op_hash(void) { uint8_t h[32]; c_sha256(h, hbuf, sizeof hbuf); return 0; }

typedef struct { const char *name; int (*fn)(void); } op_t;
static const op_t OPS[] = {
    {"keygen", op_keygen}, {"sign", op_sign}, {"verify", op_verify},
    {"chain", op_chain}, {"manifest_full", op_full}, {"manifest_leaf", op_leaf},
    {"manifest_thumb", op_thumb}, {"manifest_chain", op_chainf}, {"sha256_8KiB", op_hash},
};

static int (*find_op(const char *name))(void) {
    for (size_t i = 0; i < sizeof OPS / sizeof OPS[0]; i++)
        if (!strcmp(OPS[i].name, name)) return OPS[i].fn;
    return NULL;
}

/* Prepare g_msg (the full manifest's Sig_structure) and a key pair. */
static int setup_alg(int v) {
    cose_t c;
    g_vec = &VECTORS[v];
    g_alg = alg_id(g_vec->alg);
    c_sha256(g_thumb, g_vec->ts_leaf, g_vec->ts_leaf_len);
    if (cose_decode(g_vec->full, g_vec->full_len, &c)) return -1;
    g_msg_len = sig_structure(g_msg, c.prot, CLAIM, sizeof CLAIM);
    if (op_keygen() || op_sign()) return -1;
    return 0;
}

#ifndef ENERGY
/* ----------------------------------------------------------- timing build */

#define MAXN 100
#ifdef HW_CRYPTO
#define HW_PASSES 1
#define HW_ON c_use_hw
#define HW_HAS(a) hw_supports(a)
#else
#define HW_PASSES 0
#define HW_ON 0
#define HW_HAS(a) 0
#endif
static uint32_t samples[MAXN];

static int cmp_u32(const void *a, const void *b) {
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

/* rx_len > 0 marks a whole-manifest verifier: its RAM is the received
 * manifest plus the Sig_structure it rebuilt, both live at once. */
static void bench(const char *name, int (*fn)(void), int n, size_t rx_len) {
    int ok = fn() == 0;                      /* warm-up */
    size_t extra_ram = rx_len ? rx_len + g_msg_len : 0;
    uint64_t sum = 0;
    for (int i = 0; i < n; i++) {
        uint64_t t0 = plat_ticks();
        int r = fn();
        uint64_t t1 = plat_ticks();
        ok &= r == 0;
        samples[i] = (uint32_t)(t1 - t0);
        sum += t1 - t0;
    }
    plat_stack_paint();
    fn();
    size_t stack = plat_stack_used();
    qsort(samples, (size_t)n, sizeof samples[0], cmp_u32);
    uint32_t med = n % 2 ? samples[n / 2] : (samples[n / 2 - 1] + samples[n / 2]) / 2;
    /* Integers only: the Pico SDK's printf has no floating point. */
    uint64_t us10 = (uint64_t)med * 10000000ull / plat_tick_hz();
    OUT("{\"op\":\"%s\",\"alg\":\"%s\",\"n\":%d,\"median_ticks\":%lu,\"mean_ticks\":%lu,"
        "\"min_ticks\":%lu,\"max_ticks\":%lu,\"median_us\":%lu.%lu,\"stack_bytes\":%u,"
        "\"buffers_bytes\":%u,\"hw\":%d,\"ok\":%s}",
        name, g_vec->alg, n, (unsigned long)med, (unsigned long)(sum / (uint64_t)n),
        (unsigned long)samples[0], (unsigned long)samples[n - 1], (unsigned long)(us10 / 10), (unsigned long)(us10 % 10),
        (unsigned)stack, (unsigned)extra_ram, HW_ON, ok ? "true" : "false");
}

static void bench_sha256(void) {
    for (size_t i = 0; i < sizeof hbuf; i++) hbuf[i] = (uint8_t)i;
    const int reps = 64;
    uint64_t t0 = plat_ticks();
    for (int i = 0; i < reps; i++) op_hash();
    uint64_t dt = plat_ticks() - t0;
    uint64_t us = dt * 1000000ull / plat_tick_hz();
    uint64_t kBps = us ? (uint64_t)sizeof hbuf * (uint64_t)reps * 1000ull / us : 0;  /* bytes/ms */
    OUT("{\"op\":\"sha256\",\"bytes\":%u,\"reps\":%d,\"us\":%lu,\"MBps\":%lu.%03lu,\"hw\":%d}",
        (unsigned)sizeof hbuf, reps, (unsigned long)us, (unsigned long)(kBps / 1000),
        (unsigned long)(kBps % 1000), HW_ON);
}

static void run_alg(int v) {
    if (setup_alg(v)) {
        OUT("{\"op\":\"error\",\"alg\":\"%s\",\"what\":\"setup\"}", VECTORS[v].alg);
        return;
    }
    int pq = alg_is_pq(g_alg);
    OUT("{\"op\":\"sizes\",\"alg\":\"%s\",\"backend\":\"%s\",\"full_bytes\":%u,"
        "\"chain_bytes\":%u,"
        "\"leaf_bytes\":%u,\"thumb_bytes\":%u,\"sig_structure_bytes\":%u,\"sig_bytes\":%u,\"hw\":%d}",
        g_vec->alg, backend_name(g_alg), (unsigned)g_vec->full_len,
        (unsigned)g_vec->chain_len,
        (unsigned)g_vec->leaf_len, (unsigned)g_vec->thumb_len,
        (unsigned)g_msg_len, (unsigned)g_siglen, HW_ON);
    bench("keygen", op_keygen, pq ? 5 : 20, 0);
    op_sign();
    bench("sign", op_sign, pq ? 30 : 50, 0);
    bench("verify", op_verify, pq ? 20 : 50, 0);
    bench("chain", op_chain, pq ? 10 : 20, 0);
    bench("manifest_full", op_full, pq ? 10 : 20, g_vec->full_len);
    bench("manifest_chain", op_chainf, pq ? 10 : 20, g_vec->chain_len);
    bench("manifest_leaf", op_leaf, pq ? 10 : 20, g_vec->leaf_len);
    bench("manifest_thumb", op_thumb, pq ? 10 : 20, g_vec->thumb_len);

    /* One flipped bit must be rejected, by the primitive and end to end. */
    op_sign();
    g_sig[g_siglen / 2] ^= 1;
    int rej = op_verify() != 0;
    g_sig[g_siglen / 2] ^= 1;
    int acc = op_verify() == 0;
    receive(g_vec->full, g_vec->full_len);
    g_rx[g_rx_len - 10] ^= 1;
    int rej_m = verify_received(0) != 0;
    /* A tampered intermediate inside a conformant manifest must fail path
     * validation, and a leaf-only manifest whose intermediate the trust
     * store lacks must fail too. */
    int rej_i = 0, rej_noint = 0;
    {
        cose_t c2;
        receive(g_vec->chain, g_vec->chain_len);
        if (!cose_decode(g_rx, g_rx_len, &c2) && c2.ncerts == 2) {
            ((uint8_t *)c2.certs[1].p)[c2.certs[1].n / 2] ^= 1;
            rej_i = verify_received(3) != 0;
        }
        receive(g_vec->leaf, g_vec->leaf_len);
        rej_noint = 1;
        {
            /* Path from the leaf straight to the root, as a verifier holding
             * only the root would have to try. */
            cose_t c3; cert_t l3, r3;
            if (!cose_decode(g_rx, g_rx_len, &c3) && c3.ncerts == 1 &&
                !x509_parse(c3.certs[0], &l3) &&
                !x509_parse(sp(g_vec->ts_root, g_vec->ts_root_len), &r3))
                rej_noint = cert_verify(g_alg, &l3, &r3) != 0;
        }
    }
    OUT("{\"op\":\"negative\",\"alg\":\"%s\",\"rejects_flipped_bit\":%s,"
        "\"accepts_original\":%s,\"rejects_tampered_manifest\":%s,"
        "\"rejects_tampered_intermediate\":%s,\"rejects_missing_intermediate\":%s,"
        "\"hw\":%d}", g_vec->alg,
        rej ? "true" : "false", acc ? "true" : "false", rej_m ? "true" : "false",
        rej_i ? "true" : "false", rej_noint ? "true" : "false", HW_ON);
}

void credential_main(void) {
    c_init();
    OUT("{\"op\":\"env\",%s}", plat_env_json());
    for (int hw = 0; hw <= HW_PASSES; hw++) {
#ifdef HW_CRYPTO
        c_use_hw = hw;
#endif
        bench_sha256();
        for (int v = 0; v < N_VECTORS; v++) {
            if (hw && !HW_HAS(alg_id(VECTORS[v].alg))) continue;
            run_alg(v);
        }
    }
    OUT("{\"op\":\"done\"}");
}

#else
/* ----------------------------------------------------------- energy build */

#ifdef LINEA_SCHEDULE
#include LINEA_SCHEDULE
#else
#include "schedule.h"
#endif

static void window(int (*fn)(void), int k) {
    plat_marker(1);
    for (int i = 0; i < k; i++) fn();
    plat_marker(0);
    plat_delay_ms(GAP_MS);
}

void credential_main(void) {
    c_init();
    for (size_t i = 0; i < sizeof hbuf; i++) hbuf[i] = (uint8_t)i;
    plat_delay_ms(START_IDLE_MS);           /* idle baseline before anything */
    for (int i = 0; i < SYNC_PULSES; i++) { /* three short pulses: start */
        plat_marker(1); plat_delay_ms(SYNC_MS); plat_marker(0); plat_delay_ms(SYNC_MS);
    }
    plat_delay_ms(GAP_MS);
    for (int round = 0; round < ROUNDS; round++) {
        for (size_t s = 0; s < N_SCHEDULE; s++) {
            const sched_t *e = &SCHEDULE[s];
            int v;
            for (v = 0; v < N_VECTORS; v++)
                if (!strcmp(VECTORS[v].alg, e->alg)) break;
#ifdef HW_CRYPTO
            c_use_hw = e->hw;
#endif
            if (v == N_VECTORS) {                 /* no algorithm: e.g. SHA-256 alone */
                int (*fn)(void) = find_op(e->op);
                window(fn ? fn : op_hash, fn ? e->k : 1);
                continue;
            }
            if (setup_alg(v)) { window(op_hash, 1); continue; }
            if (!strcmp(e->op, "verify")) op_sign();
            window(find_op(e->op), e->k);
        }
    }
    OUT("{\"op\":\"done\"}");
    for (;;) plat_delay_ms(1000);
}
#endif
