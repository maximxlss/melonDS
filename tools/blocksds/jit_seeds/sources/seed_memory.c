// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t acc = 0;
    seed_fill_mem(0x31415926u);

    volatile uint8_t *b = (volatile uint8_t *)g_mem;
    for (unsigned i = 0; i < sizeof(g_mem); i++)
        b[i] = (uint8_t)(b[i] ^ (i * 3u));

    volatile uint16_t *h = (volatile uint16_t *)g_mem;
    for (unsigned i = 0; i < (sizeof(g_mem) / 2u); i++)
        acc += h[i] ^ (uint16_t)(i * 0x11u);

    volatile uint32_t *w = g_mem;
    for (unsigned i = 0; i < 64; i++)
    {
        uint32_t v = w[i];
        v ^= seed_rotl32(v, (i & 7u) + 1u);
        w[i] = v;
        acc ^= v;
    }

    g_sink = acc ^ seed_sum_mem(w, 64);
}
