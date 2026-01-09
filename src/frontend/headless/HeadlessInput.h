#ifndef MELONDS_HEADLESS_INPUT_H
#define MELONDS_HEADLESS_INPUT_H

#include <cstdint>

#include "NDS.h"

namespace melonDS::Headless
{
class Input
{
public:
    void SetKeyMask(u32 mask) { keyMask = mask; }
    u32 GetKeyMask() const { return keyMask; }

    // The DS keypad is active-low: passing a bit in mask clears that key.
    void PressKeys(u32 mask) { keyMask &= ~mask; }
    void ReleaseKeys(u32 mask) { keyMask |= mask; }

    void Touch(u16 x, u16 y)
    {
        touching = true;
        touchX = x;
        touchY = y;
    }
    void ReleaseTouch() { touching = false; }

    void SetLidClosed(bool closed)
    {
        lidClosed = closed;
        lidDirty = true;
    }

    void Apply(NDS& nds)
    {
        nds.SetKeyMask(keyMask);
        if (touching)
            nds.TouchScreen(touchX, touchY);
        else
            nds.ReleaseScreen();
        if (lidDirty)
        {
            nds.SetLidClosed(lidClosed);
            lidDirty = false;
        }
    }

private:
    u32 keyMask = 0xFFF;
    bool touching = false;
    u16 touchX = 0;
    u16 touchY = 0;
    bool lidClosed = false;
    bool lidDirty = false;
};
}

#endif
