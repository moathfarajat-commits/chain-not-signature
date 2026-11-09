/* Shared by ble_tx (DK1, measured by the PPK2) and ble_rx (DK2). */
#ifndef BLE_COMMON_H
#define BLE_COMMON_H
#include <zephyr/bluetooth/uuid.h>

/* 128-bit UUIDs private to this experiment */
#define LINEA_SVC_VAL  BT_UUID_128_ENCODE(0x6c696e65, 0x6100, 0x4c41, 0x8000, 0x4c696e65c2a0)
#define LINEA_TX_VAL   BT_UUID_128_ENCODE(0x6c696e65, 0x6101, 0x4c41, 0x8000, 0x4c696e65c2a0)
#define BT_UUID_LINEA_SVC BT_UUID_DECLARE_128(LINEA_SVC_VAL)
#define BT_UUID_LINEA_TX  BT_UUID_DECLARE_128(LINEA_TX_VAL)

/* Link settings; the receiver asks for them, the sender accepts. */
#define LINEA_CONN_INTERVAL 12          /* x 1.25 ms = 15 ms */
#define LINEA_SUPERVISION   400         /* x 10 ms */

static inline const uint8_t *form_bytes(const vec_t *v, int f, size_t *n) {
    if (f == 0) { *n = v->full_len; return v->full; }
    if (f == 1) { *n = v->leaf_len; return v->leaf; }
    if (f == 3) { *n = v->chain_len; return v->chain; }
    *n = v->thumb_len; return v->thumb;
}
static inline int form_id(const char *s) {   /* full, leaf, thumb, chain */
    return s[0] == 'f' ? 0 : s[0] == 'l' ? 1 : s[0] == 'c' ? 3 : 2;
}
#endif
