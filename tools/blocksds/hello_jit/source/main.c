// SPDX-License-Identifier: CC0-1.0
// SPDX-FileContributor: melonDS fuzzing harness example

#include <nds.h>
int main(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    while (1)
        swiWaitForVBlank();

    return 0;
}
