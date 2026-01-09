// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t v = 0x13579BDFu;
    unsigned i = 0;
    unsigned loops = 0;

start:
    v ^= (v << 3) + i;
    if (v & 1u)
        goto odd;
    goto even;

odd:
    v = seed_mix32(v + 0x11111111u);
    if ((v & 0x80u) != 0)
        goto tail;
    goto cont;

even:
    v = seed_rotl32(v, (v & 7u) + 1u);
    if ((v & 0x10u) == 0)
        goto tail;
    goto cont;

tail:
    v ^= (v >> 5);

cont:
    i++;
    loops += (v & 3u);
    if (i < 12)
        goto start;

    while (loops--)
        v ^= (loops * 0x01010101u);

    g_sink = v;
}
