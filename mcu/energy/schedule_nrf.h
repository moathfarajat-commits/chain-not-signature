/* Generated from schedule_nrf.json by gen_schedule.py. Do not edit. */
#ifndef SCHEDULE_H
#define SCHEDULE_H
typedef struct { const char *alg; const char *op; int k; int hw; } sched_t;
static const sched_t SCHEDULE[] = {
    {"Ed25519", "sign", 20, 0},
    {"Ed25519", "verify", 20, 0},
    {"Ed25519", "manifest_full", 10, 0},
    {"Ed25519", "manifest_thumb", 10, 0},
    {"Ed25519", "sign", 20, 1},
    {"Ed25519", "verify", 20, 1},
    {"Ed25519", "manifest_full", 10, 1},
    {"Ed25519", "manifest_thumb", 10, 1},
    {"ES256", "sign", 10, 0},
    {"ES256", "verify", 10, 0},
    {"ES256", "manifest_full", 5, 0},
    {"ES256", "manifest_thumb", 5, 0},
    {"ES256", "sign", 10, 1},
    {"ES256", "verify", 10, 1},
    {"ES256", "manifest_full", 5, 1},
    {"ES256", "manifest_thumb", 5, 1},
    {"ML-DSA-44", "sign", 5, 0},
    {"ML-DSA-44", "verify", 10, 0},
    {"ML-DSA-44", "manifest_full", 5, 0},
    {"ML-DSA-44", "manifest_thumb", 5, 0},
    {"ML-DSA-65", "sign", 5, 0},
    {"ML-DSA-65", "verify", 10, 0},
    {"ML-DSA-65", "manifest_full", 5, 0},
    {"ML-DSA-65", "manifest_thumb", 5, 0},
    {"ML-DSA-87", "sign", 5, 0},
    {"ML-DSA-87", "verify", 10, 0},
    {"ML-DSA-87", "manifest_full", 5, 0},
    {"ML-DSA-87", "manifest_thumb", 5, 0},
    {"-", "sha256_8KiB", 20, 0},
    {"-", "sha256_8KiB", 20, 1}
};
#define N_SCHEDULE 30
#define ROUNDS 3
#define GAP_MS 300
#define START_IDLE_MS 2000
#define SYNC_PULSES 3
#define SYNC_MS 50
#endif
