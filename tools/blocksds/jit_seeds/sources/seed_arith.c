// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t v = 0x12345678u;
    uint32_t acc = 0;

    seed_fill_mem(v);

    for (unsigned i = 0; i < 32; i++)
    {
        v = seed_mix32(v + (i * 0x9E3779B9u));
        v ^= seed_rotl32(v, (i & 7u) + 1u);

        uint32_t mul = v;
        __asm__ volatile("mul %0, %0, %1" : "+r"(mul) : "r"(i + 1u));

        acc += v ^ mul;
        if (v & 1u)
            v += 0x13579BDFu;
        else
            v ^= 0xA5A5A5A5u;

        acc ^= g_mem[i & 63u];
    }

    g_sink = acc ^ v;
}
