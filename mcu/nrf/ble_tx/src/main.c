/* DK1 (nRF52840): sends credential manifests over Bluetooth LE.
 *
 * Waits for DK2 to connect, raise the link to 2M PHY with 251-byte data
 * length and a 247-byte ATT MTU, and subscribe. Then, after an idle baseline
 * and three sync pulses on P0.03, runs schedule_ble.json: for each entry the
 * marker goes high, the manifest in the given carriage form is sent k times
 * as notifications of MTU-3 bytes, and the marker drops once the link layer
 * has had every packet acknowledged. The PPK2 (ampere mode at P22, SB40 cut)
 * integrates DK1's current over each window. */
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <hal/nrf_gpio.h>
#include "vectors.h"
#include "schedule_ble.h"
#include "ble_common.h"

#define MARKER_PIN NRF_GPIO_PIN_MAP(0, 3)
#define INFLIGHT 8                       /* notifications queued at once */

static struct bt_conn *conn;
static volatile bool subscribed, phy_2m, dle_ok;
static K_SEM_DEFINE(tx_sem, INFLIGHT, INFLIGHT);
static K_SEM_DEFINE(link_ready, 0, 1);

static void ccc_changed(const struct bt_gatt_attr *attr, uint16_t value) {
    subscribed = value == BT_GATT_CCC_NOTIFY;
}

BT_GATT_SERVICE_DEFINE(linea_svc,
    BT_GATT_PRIMARY_SERVICE(BT_UUID_LINEA_SVC),
    BT_GATT_CHARACTERISTIC(BT_UUID_LINEA_TX, BT_GATT_CHRC_NOTIFY, BT_GATT_PERM_NONE,
                           NULL, NULL, NULL),
    BT_GATT_CCC(ccc_changed, BT_GATT_PERM_READ | BT_GATT_PERM_WRITE),
);

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA_BYTES(BT_DATA_UUID128_ALL, LINEA_SVC_VAL),
};

static void connected(struct bt_conn *c, uint8_t err) {
    if (!err) conn = bt_conn_ref(c);
}
static void disconnected(struct bt_conn *c, uint8_t reason) {
    if (conn) { bt_conn_unref(conn); conn = NULL; }
    subscribed = phy_2m = dle_ok = false;
}
static void phy_updated(struct bt_conn *c, struct bt_conn_le_phy_info *p) {
    phy_2m = p->tx_phy == BT_GAP_LE_PHY_2M && p->rx_phy == BT_GAP_LE_PHY_2M;
}
static void dle_updated(struct bt_conn *c, struct bt_conn_le_data_len_info *i) {
    dle_ok = i->tx_max_len >= 251;
}
BT_CONN_CB_DEFINE(conn_cbs) = {
    .connected = connected,
    .disconnected = disconnected,
    .le_phy_updated = phy_updated,
    .le_data_len_updated = dle_updated,
};

static void sent(struct bt_conn *c, void *user_data) { k_sem_give(&tx_sem); }

static void send_bytes(const uint8_t *p, size_t n) {
    const struct bt_gatt_attr *attr = &linea_svc.attrs[1];
    size_t chunk = bt_gatt_get_mtu(conn) - 3;
    while (n) {
        size_t m = n < chunk ? n : chunk;
        struct bt_gatt_notify_params np = {
            .attr = attr, .data = p, .len = m, .func = sent,
        };
        k_sem_take(&tx_sem, K_FOREVER);
        while (bt_gatt_notify_cb(conn, &np) != 0) {   /* buffers full: wait */
            k_msleep(1);
            if (!conn) return;
        }
        p += m;
        n -= m;
    }
}

/* Every queued notification acknowledged. */
static void drain(void) {
    for (int i = 0; i < INFLIGHT; i++) k_sem_take(&tx_sem, K_FOREVER);
    for (int i = 0; i < INFLIGHT; i++) k_sem_give(&tx_sem);
}

static void marker(int on) { nrf_gpio_pin_write(MARKER_PIN, on); }

int main(void) {
    nrf_gpio_cfg_output(MARKER_PIN);
    marker(0);
    if (bt_enable(NULL)) return 0;
    bt_le_adv_start(BT_LE_ADV_CONN_FAST_1, ad, ARRAY_SIZE(ad), NULL, 0);

    /* DK2 drives the link set-up; give it up to 20 s to finish. */
    for (int i = 0; i < 2000 && !(conn && subscribed && phy_2m && dle_ok &&
                                  bt_gatt_get_mtu(conn) >= 247); i++)
        k_msleep(10);
    bt_le_adv_stop();
    if (!conn || !subscribed) return 0;

    k_msleep(START_IDLE_MS);
    for (int i = 0; i < SYNC_PULSES; i++) {
        marker(1); k_msleep(SYNC_MS); marker(0); k_msleep(SYNC_MS);
    }
    k_msleep(GAP_MS);
    for (int r = 0; r < ROUNDS && conn; r++) {
        for (int s = 0; s < N_SCHEDULE && conn; s++) {
            const sched_t *e = &SCHEDULE[s];
            int v;
            for (v = 0; v < N_VECTORS; v++)
                if (!strcmp(VECTORS[v].alg, e->alg)) break;
            size_t n = 0;
            const uint8_t *b = v < N_VECTORS ? form_bytes(&VECTORS[v], form_id(e->op), &n) : NULL;
            marker(1);
            for (int k = 0; k < e->k && b; k++) send_bytes(b, n);
            drain();
            marker(0);
            k_msleep(GAP_MS);
        }
    }
    return 0;
}
