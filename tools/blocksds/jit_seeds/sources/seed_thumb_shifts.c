// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t v = 0xA5A5A5A5u;
    uint32_t acc = 0;

    for (unsigned i = 0; i < 24; i++)
    {
        uint32_t s = (i & 7u) + 1u;
        v ^= (v << s);
        v ^= (v >> (s >> 1));
        v = seed_rotl32(v, s);

        uint32_t r = v;
        __asm__ volatile("lsr %0, %0, %1" : "+r"(r) : "r"(s));
        acc ^= r + v + i;

        if (v & 0x100u)
            v ^= 0x0F0F0F0Fu;
    }

    g_sink = acc ^ v;
}
