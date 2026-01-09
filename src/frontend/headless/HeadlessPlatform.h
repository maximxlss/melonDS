#ifndef MELONDS_HEADLESS_PLATFORM_H
#define MELONDS_HEADLESS_PLATFORM_H

#include <filesystem>
#include <string>

#include "Platform.h"

namespace melonDS::Platform
{
// Headless-only helpers for configuring platform behavior.
void Headless_SetLocalBasePath(const std::filesystem::path& path);
void Headless_SetNDSSavePath(const std::string& path);
void Headless_SetGBASavePath(const std::string& path);
void Headless_SetFirmwarePath(const std::string& path);

bool Headless_StopRequested();
StopReason Headless_StopReason();

void Headless_SetAddonKeyDown(KeyType type, bool down);
void Headless_SetMotionValue(MotionQueryType type, float value);
}

#endif
