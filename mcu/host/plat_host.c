/* Host build: checks the parsers, the carriage forms and the negative tests
 * against the generated vectors before anything goes on a board. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "plat.h"

void credential_main(void);

void plat_init(void) { srand(12345); }
uint32_t plat_rand32(void) { return (uint32_t)rand() ^ ((uint32_t)rand() << 16); }
uint64_t plat_ticks(void) {
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000u + (uint64_t)t.tv_nsec;
}
uint32_t plat_tick_hz(void) { return 1000000000u; }
void plat_marker(int on) { (void)on; }
void plat_print(const char *line) { puts(line); fflush(stdout); }
void plat_delay_ms(uint32_t ms) { (void)ms; }
void plat_stack_paint(void) {}
size_t plat_stack_used(void) { return 0; }
const char *plat_env_json(void) { return "\"board\":\"host\""; }

int main(void) { plat_init(); credential_main(); return 0; }
