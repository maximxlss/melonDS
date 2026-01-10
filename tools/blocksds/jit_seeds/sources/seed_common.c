// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

extern uint32_t __sp_usr;

void seed_main(void);
void seed_poweroff(void);

__attribute__((naked, section(".crt0")))
void _start(void)
{
    __asm__ volatile(
        "ldr r0, =__sp_usr\n"
        "mov sp, r0\n"
        "bl seed_main\n"
        "bl seed_poweroff\n"
        "b .\n"
    );
}

volatile uint32_t g_sink;
volatile uint32_t g_mem[64];

void seed_poweroff(void)
{
    volatile uint16_t* spicnt = (volatile uint16_t*)0x040001C0;
    volatile uint16_t* spidata = (volatile uint16_t*)0x040001C2;
    *spicnt = 0x8800u; // enable + hold, PowerMan selected
    *spidata = 0x0000u; // register index 0
    while (*spicnt & 0x00000080u) {}
    *spidata = 0x0040u; // bit 6 => power off
    while (*spicnt & 0x00000080u) {}
    *spicnt = 0x8000u; // release chipselect
}
