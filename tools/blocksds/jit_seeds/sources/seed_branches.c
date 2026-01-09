// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness seeds

#include "seed_common.h"

__attribute__((used))
void seed_main(void)
{
    uint32_t v = 0xCAFEBABEu;
    unsigned i = 0;

    goto state0;

state0:
    v ^= 0x11111111u;
    if (v & 1u)
        goto state1;
    goto state2;

state1:
    v = seed_mix32(v + i);
    if (v & 0x10u)
        goto state3;
    goto loop;

state2:
    v = seed_rotl32(v, (v & 7u) + 1u);
    if ((v & 3u) == 0)
        goto state3;
    goto loop;

state3:
    v ^= (v >> 3);
    if ((v & 0x80u) != 0)
        goto state1;
    goto loop;

loop:
    i++;
    if (i < 12)
        goto state0;

    switch (v & 7u)
    {
    case 0: v ^= 0x01010101u; break;
    case 1: v += 0x02020202u; break;
    case 2: v -= 0x03030303u; break;
    case 3: v ^= 0x04040404u; break;
    case 4: v += 0x05050505u; break;
    default: v = seed_mix32(v); break;
    }

#if defined(__GNUC__)
    {
        static void *dispatch[] = { &&L0, &&L1, &&L2, &&L3 };
        goto *dispatch[v & 3u];
L0: v ^= 0xAA55AA55u; goto done;
L1: v += 0x12345678u; goto done;
L2: v = seed_rotl32(v, 9); goto done;
L3: v = seed_mix32(v ^ 0x0F0F0F0Fu); goto done;
    }
#endif

done:
    g_sink = v;
}
