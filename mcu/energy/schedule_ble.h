/* Generated from schedule_ble.json by gen_schedule.py. Do not edit. */
#ifndef SCHEDULE_H
#define SCHEDULE_H
typedef struct { const char *alg; const char *op; int k; int hw; } sched_t;
static const sched_t SCHEDULE[] = {
    {"Ed25519", "full", 10, 0},
    {"Ed25519", "leaf", 10, 0},
    {"Ed25519", "thumb", 10, 0},
    {"ES256", "full", 10, 0},
    {"ES256", "leaf", 10, 0},
    {"ES256", "thumb", 10, 0},
    {"ML-DSA-44", "full", 10, 0},
    {"ML-DSA-44", "leaf", 10, 0},
    {"ML-DSA-44", "thumb", 10, 0},
    {"ML-DSA-65", "full", 10, 0},
    {"ML-DSA-65", "leaf", 10, 0},
    {"ML-DSA-65", "thumb", 10, 0},
    {"ML-DSA-87", "full", 10, 0},
    {"ML-DSA-87", "leaf", 10, 0},
    {"ML-DSA-87", "thumb", 10, 0}
};
#define N_SCHEDULE 15
#define ROUNDS 3
#define GAP_MS 500
#define START_IDLE_MS 2000
#define SYNC_PULSES 3
#define SYNC_MS 50
#endif
