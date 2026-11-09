/* NUCLEO-L4R5ZI (STM32L4R5ZI, Cortex-M4F, 2 MB flash, 640 KB SRAM), on
 * pqm4's HAL: LPUART1 through the ST-LINK virtual COM port at 38400 baud,
 * SysTick counting core cycles. CLOCK_MHZ selects the clock:
 *   20  pqm4's benchmark setting (HSI16 -> PLL 20 MHz, zero flash wait
 *       states), comparable with published pqm4 cycle counts;
 *   80  the fastest clock in the core's normal voltage mode (R1MODE = 1),
 *       HSI16 -> PLL N=10, R=2, four flash wait states.
 * PA3 (CN9 pin A0) is the marker for the PPK2. */
#include <stdio.h>
#include <libopencm3/stm32/rcc.h>
#include <libopencm3/stm32/gpio.h>
#include <libopencm3/stm32/usart.h>
#include <libopencm3/stm32/flash.h>
#include <libopencm3/stm32/rng.h>
#include <libopencm3/stm32/pwr.h>
#include "hal.h"
#include "plat.h"

#ifndef CLOCK_MHZ
#define CLOCK_MHZ 20
#endif
#ifndef PQM4_COMMIT
#define PQM4_COMMIT "unknown"
#endif

void credential_main(void);
void _rcc_set_main_pll(uint32_t source, uint32_t pllm, uint32_t plln, uint32_t pllp,
                       uint32_t pllq, uint32_t pllr);

#define PWR_CR5_REG (*(volatile uint32_t *)0x40007080u)
#define PWR_CR5_R1MODE (1u << 8)

static uint32_t clock_hz = 20000000u;
static int flash_ws = 0;

static void clock_80mhz(void) {
    rcc_set_sysclk_source(RCC_CFGR_SW_HSI16);
    rcc_wait_for_sysclk_status(RCC_HSI16);
    rcc_osc_off(RCC_PLL);
    while (rcc_is_osc_ready(RCC_PLL));
    _rcc_set_main_pll(RCC_PLLCFGR_PLLSRC_HSI16, 1, 10, 2,
                      RCC_PLLCFGR_PLLQ_DIV2, RCC_PLLCFGR_PLLR_DIV2);
    rcc_osc_on(RCC_PLL);
    rcc_wait_for_osc_ready(RCC_PLL);
    flash_set_ws(FLASH_ACR_LATENCY_4WS);       /* before raising the clock */
    rcc_set_sysclk_source(RCC_CFGR_SW_PLL);
    rcc_wait_for_sysclk_status(RCC_PLL);
    rcc_ahb_frequency = rcc_apb1_frequency = rcc_apb2_frequency = 80000000u;
    usart_disable(LPUART1);
    usart_set_baudrate(LPUART1, 38400);
    usart_enable(LPUART1);
    clock_hz = 80000000u;
    flash_ws = 4;
}

void plat_init(void) {
    hal_setup(CLOCK_BENCHMARK);
    PWR_CR5_REG |= PWR_CR5_R1MODE;             /* normal mode, stated rather than assumed */
#if CLOCK_MHZ == 80
    clock_80mhz();
#elif CLOCK_MHZ != 20
#error CLOCK_MHZ must be 20 or 80
#endif
    rcc_periph_clock_enable(RCC_GPIOA);
    gpio_mode_setup(GPIOA, GPIO_MODE_OUTPUT, GPIO_PUPD_NONE, GPIO3);
    gpio_set_output_options(GPIOA, GPIO_OTYPE_PP, GPIO_OSPEED_2MHZ, GPIO3);
    gpio_clear(GPIOA, GPIO3);
}

uint32_t plat_rand32(void) { return rng_get_random_blocking(); }
uint64_t plat_ticks(void) { return hal_get_time(); }
uint32_t plat_tick_hz(void) { return clock_hz; }
void plat_marker(int on) { if (on) gpio_set(GPIOA, GPIO3); else gpio_clear(GPIOA, GPIO3); }
void plat_print(const char *line) { hal_send_str(line); }

/* Sleep (WFI) between SysTick wake-ups, so the gaps in an energy run show the
 * board idle rather than spinning. The gap can overrun by one SysTick period
 * (2^24 cycles); the PPK2 runner times windows from the marker, not the clock. */
void plat_delay_ms(uint32_t ms) {
    uint64_t end = hal_get_time() + (uint64_t)ms * (clock_hz / 1000u);
    while (hal_get_time() < end) __asm volatile ("wfi");
}

void plat_stack_paint(void) { hal_spraystack(); }
size_t plat_stack_used(void) { return hal_checkstack(); }

const char *plat_env_json(void) {
    static char env[360];
    snprintf(env, sizeof env,
             "\"board\":\"NUCLEO-L4R5ZI\",\"chip\":\"STM32L4R5ZI\",\"core\":\"Cortex-M4F\","
             "\"clk_sys_hz\":%lu,\"flash_wait_states\":%d,\"r1mode\":%d,\"pqm4\":\"%s\","
             "\"compiler\":\"%s\",\"timer\":\"SysTick (core cycles)\"",
             (unsigned long)clock_hz, flash_ws, (PWR_CR5_REG & PWR_CR5_R1MODE) ? 1 : 0,
             PQM4_COMMIT, __VERSION__);
    return env;
}

/* newlib's exit path wants these; nothing here ever exits. */
void _init(void) {}
void _fini(void) {}

int main(void) {
    plat_init();
#ifndef ENERGY
    /* Time to start the capture script; it asks for a reset anyway. */
    plat_delay_ms(3000);
#endif
    credential_main();
    for (;;) __asm volatile ("wfi");
}
