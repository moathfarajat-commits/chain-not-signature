/* Raspberry Pi Pico (RP2040, Cortex-M0+, 125 MHz, code executed in place from
 * QSPI flash). The benchmark runs on core 1 with a large painted stack;
 * core 0 only brings up USB serial. GP16 is the marker for the PPK2. */
#include <stdio.h>
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "pico/rand.h"
#include "hardware/clocks.h"
#include "plat.h"

void credential_main(void);

#define MARKER_PIN 16
#define CORE1_STACK_BYTES (152 * 1024)
static uint32_t core1_stack[CORE1_STACK_BYTES / 4];
#define PAINT 0xA5A5A5A5u
static uintptr_t paint_sp;

static inline uintptr_t current_sp(void) {
    uintptr_t sp;
    __asm volatile ("mov %0, sp" : "=r"(sp));
    return sp;
}

void plat_init(void) {
    gpio_init(MARKER_PIN);
    gpio_set_dir(MARKER_PIN, GPIO_OUT);
    gpio_put(MARKER_PIN, 0);
}
uint32_t plat_rand32(void) { return get_rand_32(); }
uint64_t plat_ticks(void) { return time_us_64(); }
uint32_t plat_tick_hz(void) { return 1000000u; }
void plat_marker(int on) { gpio_put(MARKER_PIN, on != 0); }
void plat_print(const char *line) { puts(line); stdio_flush(); }
void plat_delay_ms(uint32_t ms) { sleep_ms(ms); }

void plat_stack_paint(void) {
    paint_sp = current_sp();
    uint32_t *top = (uint32_t *)(paint_sp - 64);
    for (uint32_t *w = core1_stack; w < top; w++) *w = PAINT;
}
size_t plat_stack_used(void) {
    uint32_t *w = core1_stack;
    while (*w == PAINT) w++;
    return (size_t)(paint_sp - (uintptr_t)w);
}

const char *plat_env_json(void) {
    static char env[320];
    snprintf(env, sizeof env,
             "\"board\":\"Raspberry Pi Pico\",\"chip\":\"RP2040\",\"core\":\"Cortex-M0+\","
             "\"clk_sys_hz\":%lu,\"sdk\":\"%s\",\"compiler\":\"%s\",\"xip\":true,"
             "\"timer\":\"time_us_64 (1 MHz)\",\"stack_bytes_available\":%u",
             (unsigned long)clock_get_hz(clk_sys), PICO_SDK_VERSION_STRING, __VERSION__,
             (unsigned)CORE1_STACK_BYTES);
    return env;
}

static void core1_main(void) { credential_main(); for (;;) tight_loop_contents(); }

int main(void) {
    stdio_init_all();
    plat_init();
#ifndef ENERGY
    while (!stdio_usb_connected()) sleep_ms(100);
    sleep_ms(1500);
#endif
    multicore_launch_core1_with_stack(core1_main, core1_stack, sizeof core1_stack);
    for (;;) __wfe();
}
