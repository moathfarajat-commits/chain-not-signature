/* What each board provides to the credential benchmark. */
#ifndef PLAT_H
#define PLAT_H
#include <stdint.h>
#include <stddef.h>

void plat_init(void);
uint32_t plat_rand32(void);
uint64_t plat_ticks(void);          /* monotonic; plat_tick_hz() per second */
uint32_t plat_tick_hz(void);
void plat_marker(int on);           /* PPK2 logic input: high while an op runs */
void plat_print(const char *line);  /* one line, newline appended */
void plat_delay_ms(uint32_t ms);
void plat_stack_paint(void);        /* before the measured call */
size_t plat_stack_used(void);       /* peak bytes since the paint */
const char *plat_env_json(void);    /* the "env" object, without braces */

#endif
