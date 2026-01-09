// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

typedef struct
{
    uint32_t a;
    uint32_t b;
    uint16_t c;
    uint8_t d;
    uint8_t e;
} Packed;

static SEED_NOINLINE uint32_t stack_sum(const Packed *p, unsigned n)
{
    uint32_t sum = 0;
    for (unsigned i = 0; i < n; i++)
        sum += p[i].a ^ p[i].b ^ p[i].c ^ p[i].d ^ p[i].e;
    return sum;
}

__attribute__((used))
void seed_main(void)
{
    Packed items[8];
    uint32_t v = 0x0F0E0D0Cu;

    for (unsigned i = 0; i < 8; i++)
    {
        items[i].a = v + i;
        items[i].b = seed_rotl32(v, i + 1u);
        items[i].c = (uint16_t)(v >> (i & 3u));
        items[i].d = (uint8_t)(v ^ i);
        items[i].e = (uint8_t)(v + (i * 3u));
    }

    __asm__ volatile("push {r4-r7}" ::: "memory");
    v ^= stack_sum(items, 8);
    __asm__ volatile("pop {r4-r7}" ::: "memory");

    g_sink = v;
}
