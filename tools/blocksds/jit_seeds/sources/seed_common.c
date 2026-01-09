// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

extern uint32_t __sp_usr;

void seed_main(void);

__attribute__((naked, section(".crt0")))
void _start(void)
{
    __asm__ volatile(
        "ldr r0, =__sp_usr\n"
        "mov sp, r0\n"
        "bl seed_main\n"
        "b .\n"
    );
}

volatile uint32_t g_sink;
volatile uint32_t g_mem[64];
