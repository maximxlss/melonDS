// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t src[4] = { 0x11111111u, 0x22222222u, 0x33333333u, 0x44444444u };
    uint32_t dst[4] = { 0 };

    __asm__ volatile(
        "ldmia %0, {r2-r5}\n"
        "stmia %1, {r2-r5}\n"
        :
        : "r"(src), "r"(dst)
        : "r2", "r3", "r4", "r5", "memory"
    );

    uint32_t v = dst[0] ^ dst[1] ^ dst[2] ^ dst[3];
    g_sink = v;
}
