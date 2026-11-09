/* Receiver (nRF52840): receives credential manifests from the sender and
 * checks them. The schedule (schedule_ble.json) and the vectors are shared
 * with the sender, so the receiver knows which manifest, in which carriage
 * form, each byte belongs to. When this board is the measured one, P0.03
 * goes high at the first notification of a window and low after its last,
 * so the PPK2 integrates the receiver's energy per window. */
#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <bluetooth/scan.h>
#include <bluetooth/gatt_dm.h>
#include <ncs_version.h>
#include <hal/nrf_gpio.h>
#include "vectors.h"
#include "schedule_ble.h"
#include "ble_common.h"

#define MARKER_PIN NRF_GPIO_PIN_MAP(0, 3)
static struct bt_conn *conn;
static struct bt_gatt_subscribe_params sub;
static uint8_t rx[28 * 1024];

/* where we are in the schedule */
static int round_i, entry_i, rep_i;
static size_t got, want;
static const uint8_t *expect;
static uint32_t t_first;
static int ok_count, bad_count;

struct winrec { int round, entry, k, ok, last; unsigned bytes; uint32_t cyc_sum, cyc_max; };
static struct winrec win, done_win;

static void print_fn(struct k_work *w) {
    struct winrec r = done_win;
    const sched_t *e = &SCHEDULE[r.entry];
    uint32_t hz = sys_clock_hw_cycles_per_sec();
    uint32_t mean_us = (uint32_t)((uint64_t)r.cyc_sum * 1000000u / hz / (uint32_t)r.k);
    uint32_t max_us = (uint32_t)((uint64_t)r.cyc_max * 1000000u / hz);
    printk("{\"op\":\"rx\",\"round\":%d,\"alg\":\"%s\",\"form\":\"%s\",\"k\":%d,"
           "\"bytes\":%u,\"ok\":%d,\"first_to_last_us_mean\":%u,\"first_to_last_us_max\":%u}\n",
           r.round, e->alg, e->op, r.k, r.bytes, r.ok, mean_us, max_us);
    if (r.last)
        printk("{\"op\":\"done\",\"ok\":%d,\"bad\":%d}\n", ok_count, bad_count);
}
static K_WORK_DEFINE(print_work, print_fn);

static void next_expected(void) {
    while (round_i < ROUNDS) {
        if (entry_i >= N_SCHEDULE) { entry_i = 0; round_i++; continue; }
        const sched_t *e = &SCHEDULE[entry_i];
        int v;
        for (v = 0; v < N_VECTORS; v++)
            if (!strcmp(VECTORS[v].alg, e->alg)) break;
        if (v == N_VECTORS) { entry_i++; continue; }
        expect = form_bytes(&VECTORS[v], form_id(e->op), &want);
        got = 0;
        return;
    }
    expect = NULL;
}

static uint8_t on_notify(struct bt_conn *c, struct bt_gatt_subscribe_params *p,
                         const void *data, uint16_t len) {
    if (!data) return BT_GATT_ITER_STOP;
    if (!expect) return BT_GATT_ITER_CONTINUE;
    if (got == 0) {
        t_first = k_cycle_get_32();
        if (rep_i == 0) nrf_gpio_pin_write(MARKER_PIN, 1);   /* window opens */
    }
    if (got + len <= sizeof rx) memcpy(rx + got, data, len);
    got += len;
    if (got >= want) {
        uint32_t dt = k_cycle_get_32() - t_first;
        bool ok = got == want && memcmp(rx, expect, want) == 0;
        ok ? ok_count++ : bad_count++;
        win.bytes = (unsigned)got;
        win.ok += ok;
        win.cyc_sum += dt;
        if (dt > win.cyc_max) win.cyc_max = dt;
        if (++rep_i >= SCHEDULE[entry_i].k) {
            nrf_gpio_pin_write(MARKER_PIN, 0);                  /* window closes */
            /* window over: hand the line to the work queue so this callback
             * never waits on the UART while DK1 is still sending */
            win.round = round_i;
            win.entry = entry_i;
            win.k = rep_i;
            done_win = win;
            memset(&win, 0, sizeof win);
            rep_i = 0;
            entry_i++;
            next_expected();
            done_win.last = expect == NULL;
            k_work_submit(&print_work);
        } else {
            got = 0;
        }
    }
    return BT_GATT_ITER_CONTINUE;
}

static void discovered(struct bt_gatt_dm *dm, void *ctx) {
    const struct bt_gatt_dm_attr *chrc = bt_gatt_dm_char_by_uuid(dm, BT_UUID_LINEA_TX);
    const struct bt_gatt_dm_attr *val = chrc ? bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_LINEA_TX) : NULL;
    const struct bt_gatt_dm_attr *ccc = chrc ? bt_gatt_dm_desc_by_uuid(dm, chrc, BT_UUID_GATT_CCC) : NULL;
    if (val && ccc) {
        sub.notify = on_notify;
        sub.value = BT_GATT_CCC_NOTIFY;
        sub.value_handle = val->handle;
        sub.ccc_handle = ccc->handle;
        round_i = entry_i = rep_i = 0;
        next_expected();
        bt_gatt_subscribe(conn, &sub);
        printk("{\"op\":\"subscribed\"}\n");
    }
    bt_gatt_dm_data_release(dm);
}
static void dm_not_found(struct bt_conn *c, void *ctx) { printk("{\"op\":\"error\",\"what\":\"service not found\"}\n"); }
static void dm_error(struct bt_conn *c, int err, void *ctx) { printk("{\"op\":\"error\",\"what\":\"discovery %d\"}\n", err); }
static const struct bt_gatt_dm_cb dm_cb = {
    .completed = discovered, .service_not_found = dm_not_found, .error_found = dm_error,
};

static struct bt_gatt_exchange_params mtu_params;
static void mtu_done(struct bt_conn *c, uint8_t err, struct bt_gatt_exchange_params *p) {
    printk("{\"op\":\"link\",\"att_mtu\":%u}\n", bt_gatt_get_mtu(c));
    bt_gatt_dm_start(c, BT_UUID_LINEA_SVC, &dm_cb, NULL);
}

/* Link set-up runs on the main thread, not in the connection callback, so
 * the synchronous HCI commands it issues never wait on their own thread. */
static K_SEM_DEFINE(conn_sem, 0, 1);

static void connected(struct bt_conn *c, uint8_t err) {
    if (err) { bt_scan_start(BT_SCAN_TYPE_SCAN_ACTIVE); return; }
    conn = bt_conn_ref(c);
    k_sem_give(&conn_sem);
}

static void setup_link(struct bt_conn *c) {
    struct bt_conn_le_phy_param phy = {
        .options = BT_CONN_LE_PHY_OPT_NONE,
        .pref_tx_phy = BT_GAP_LE_PHY_2M, .pref_rx_phy = BT_GAP_LE_PHY_2M,
    };
    int e1 = bt_conn_le_phy_update(c, &phy);
    int e2 = bt_conn_le_data_len_update(c, BT_LE_DATA_LEN_PARAM_MAX);
    mtu_params.func = mtu_done;
    int e3 = bt_gatt_exchange_mtu(c, &mtu_params);
    printk("{\"op\":\"link_requests\",\"phy\":%d,\"dle\":%d,\"mtu\":%d}\n", e1, e2, e3);
}
static void disconnected(struct bt_conn *c, uint8_t reason) {
    printk("{\"op\":\"disconnected\",\"reason\":%u}\n", reason);
    if (conn) { bt_conn_unref(conn); conn = NULL; }
    bt_scan_start(BT_SCAN_TYPE_SCAN_ACTIVE);
}
static void phy_updated(struct bt_conn *c, struct bt_conn_le_phy_info *p) {
    printk("{\"op\":\"link\",\"tx_phy\":%u,\"rx_phy\":%u}\n", p->tx_phy, p->rx_phy);
}
static void dle_updated(struct bt_conn *c, struct bt_conn_le_data_len_info *i) {
    printk("{\"op\":\"link\",\"tx_max_len\":%u,\"rx_max_len\":%u}\n", i->tx_max_len, i->rx_max_len);
}
static void param_updated(struct bt_conn *c, uint16_t interval, uint16_t latency, uint16_t timeout) {
    printk("{\"op\":\"link\",\"interval_1250us\":%u,\"latency\":%u}\n", interval, latency);
}
BT_CONN_CB_DEFINE(conn_cbs) = {
    .connected = connected, .disconnected = disconnected,
    .le_phy_updated = phy_updated, .le_data_len_updated = dle_updated,
    .le_param_updated = param_updated,
};

static void scan_match(struct bt_scan_device_info *info, struct bt_scan_filter_match *f, bool connectable) {}
BT_SCAN_CB_INIT(scan_cb, scan_match, NULL, NULL, NULL);

int main(void) {
    printk("{\"op\":\"env\",\"board\":\"nRF52840-DK (receiver)\",\"ncs\":\"%s\","
           "\"conn_interval_ms\":%d.%02d,\"schedule_entries\":%d,\"rounds\":%d}\n",
           NCS_VERSION_STRING, LINEA_CONN_INTERVAL * 125 / 100, LINEA_CONN_INTERVAL * 125 % 100,
           N_SCHEDULE, ROUNDS);
    nrf_gpio_cfg_output(MARKER_PIN);
    nrf_gpio_pin_write(MARKER_PIN, 0);
    if (bt_enable(NULL)) return 0;
    static const struct bt_le_conn_param cp = {
        .interval_min = LINEA_CONN_INTERVAL, .interval_max = LINEA_CONN_INTERVAL,
        .latency = 0, .timeout = LINEA_SUPERVISION,
    };
    struct bt_scan_init_param si = {
        .connect_if_match = true, .conn_param = &cp,
    };
    bt_scan_init(&si);
    bt_scan_cb_register(&scan_cb);
    bt_scan_filter_add(BT_SCAN_FILTER_TYPE_UUID, BT_UUID_LINEA_SVC);
    bt_scan_filter_enable(BT_SCAN_UUID_FILTER, false);
    bt_scan_start(BT_SCAN_TYPE_SCAN_ACTIVE);
    for (;;) {
        k_sem_take(&conn_sem, K_FOREVER);
        k_msleep(100);
        if (conn) setup_link(conn);
    }
    return 0;
}
