// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    seed_fill_mem(0xABCDEF01u);

    volatile uint8_t *b = (volatile uint8_t *)g_mem;
    volatile uint16_t *h = (volatile uint16_t *)(b + 1);
    volatile uint32_t *w = (volatile uint32_t *)(b + 3);

    uint32_t acc = 0;
    for (unsigned i = 0; i < 8; i++)
    {
        acc ^= b[i];
        acc ^= h[i] << (i & 7u);
        acc ^= w[i];
        b[i] = (uint8_t)(b[i] + i);
    }

    g_sink = acc;
}
