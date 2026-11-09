/* QEMU mps2-an386 (Cortex-M4F model) with pqm4's MPS2 HAL. Not a timing
 * platform: it checks that the NUCLEO build (pqm4 m4f ML-DSA with renamed
 * symbols, the shared credential core) computes the right answers before the
 * image goes on the board. */
#include <stdio.h>
#include "hal.h"
#include "plat.h"

void credential_main(void);
static uint32_t lcg = 0x12345678u;

void plat_init(void) { hal_setup(CLOCK_BENCHMARK); }
uint32_t plat_rand32(void) { lcg = lcg * 1664525u + 1013904223u; return lcg ^ (lcg >> 13); }
uint64_t plat_ticks(void) { return hal_get_time(); }
uint32_t plat_tick_hz(void) { return 25000000u; }
void plat_marker(int on) { (void)on; }
void plat_print(const char *line) { hal_send_str(line); }
void plat_delay_ms(uint32_t ms) { (void)ms; }
void plat_stack_paint(void) { hal_spraystack(); }
size_t plat_stack_used(void) { return hal_checkstack(); }
const char *plat_env_json(void) { return "\"board\":\"qemu-mps2-an386\",\"note\":\"functional check only\""; }

int main(void) {
    plat_init();
    credential_main();
    return 0;
}
