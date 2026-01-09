#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "Args.h"
#include "NDS.h"
#include "NDSCart.h"
#include "Platform.h"

#include "HeadlessInput.h"
#include "HeadlessPlatform.h"

namespace fs = std::filesystem;

namespace {

struct Options
{
    std::string romPath;
    std::string savePath;
    std::string screenshotPath;
    std::uint32_t frames = 1;
    bool directBoot = false;
    bool showHelp = false;
};

void PrintUsage(const char* exe)
{
    std::printf(
        "Usage: %s [options] <rom.nds>\n"
        "\n"
        "Options:\n"
        "  --frames <n>       Number of frames to run (default: 1)\n"
        "  --direct-boot      Force direct boot\n"
        "  --save <path>      Override save path\n"
        "  --screenshot <p>   Save a BMP screenshot (256x384, top+bottom)\n"
        "  --help             Show this help\n",
        exe);
}

bool ParseU32(const char* value, std::uint32_t& out)
{
    char* end = nullptr;
    unsigned long parsed = std::strtoul(value, &end, 10);
    if (!value || !*value || (end && *end != '\0'))
        return false;
    if (parsed > 0xFFFFFFFFu)
        return false;
    out = static_cast<std::uint32_t>(parsed);
    return true;
}

Options ParseArgs(int argc, char** argv)
{
    Options opts;
    for (int i = 1; i < argc; ++i)
    {
        const char* arg = argv[i];
        if (!std::strcmp(arg, "--help") || !std::strcmp(arg, "-h"))
        {
            opts.showHelp = true;
            return opts;
        }
        if (!std::strcmp(arg, "--direct-boot"))
        {
            opts.directBoot = true;
            continue;
        }
        if (!std::strcmp(arg, "--frames") && i + 1 < argc)
        {
            if (!ParseU32(argv[++i], opts.frames))
            {
                std::fprintf(stderr, "Invalid --frames value: %s\n", argv[i]);
                opts.showHelp = true;
                return opts;
            }
            continue;
        }
        if (!std::strcmp(arg, "--save") && i + 1 < argc)
        {
            opts.savePath = argv[++i];
            continue;
        }
        if (!std::strcmp(arg, "--screenshot") && i + 1 < argc)
        {
            opts.screenshotPath = argv[++i];
            continue;
        }
        if (!opts.romPath.empty())
        {
            std::fprintf(stderr, "Unexpected argument: %s\n", arg);
            opts.showHelp = true;
            return opts;
        }
        opts.romPath = arg;
    }
    return opts;
}

bool LoadFile(const fs::path& path, std::unique_ptr<melonDS::u8[]>& outData, std::uint32_t& outLen)
{
    outLen = 0;
    outData.reset();

    melonDS::Platform::FileHandle* file = melonDS::Platform::OpenFile(path.string(), melonDS::Platform::FileMode::Read);
    if (!file)
        return false;

    std::uint64_t length = melonDS::Platform::FileLength(file);
    if (length == 0)
    {
        melonDS::Platform::CloseFile(file);
        return false;
    }

    if (length > 0xFFFFFFFFu)
    {
        melonDS::Platform::CloseFile(file);
        return false;
    }

    outLen = static_cast<std::uint32_t>(length);
    outData = std::make_unique<melonDS::u8[]>(outLen);

    melonDS::Platform::FileRewind(file);
    if (melonDS::Platform::FileRead(outData.get(), outLen, 1, file) != 1)
    {
        melonDS::Platform::CloseFile(file);
        outData.reset();
        outLen = 0;
        return false;
    }

    melonDS::Platform::CloseFile(file);
    return true;
}

std::string DefaultSavePath(const fs::path& romPath)
{
    fs::path savePath = romPath;
    savePath.replace_extension(".sav");
    return savePath.string();
}

void WriteLE16(std::ofstream& out, std::uint16_t value)
{
    const unsigned char bytes[2] = {
        static_cast<unsigned char>(value & 0xFF),
        static_cast<unsigned char>((value >> 8) & 0xFF),
    };
    out.write(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

void WriteLE32(std::ofstream& out, std::uint32_t value)
{
    const unsigned char bytes[4] = {
        static_cast<unsigned char>(value & 0xFF),
        static_cast<unsigned char>((value >> 8) & 0xFF),
        static_cast<unsigned char>((value >> 16) & 0xFF),
        static_cast<unsigned char>((value >> 24) & 0xFF),
    };
    out.write(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

bool WriteBMP(const std::string& path, const melonDS::u32* top, const melonDS::u32* bottom, int width, int height)
{
    std::ofstream out(path, std::ios::binary);
    if (!out.is_open())
        return false;

    const int totalHeight = height * 2;
    const int rowSize = (width * 3 + 3) & ~3;
    const std::uint32_t imageSize = rowSize * totalHeight;
    const std::uint32_t fileSize = 14 + 40 + imageSize;

    out.put('B');
    out.put('M');
    WriteLE32(out, fileSize);
    WriteLE16(out, 0);
    WriteLE16(out, 0);
    WriteLE32(out, 14 + 40);

    WriteLE32(out, 40);
    WriteLE32(out, static_cast<std::uint32_t>(width));
    WriteLE32(out, static_cast<std::uint32_t>(totalHeight));
    WriteLE16(out, 1);
    WriteLE16(out, 24);
    WriteLE32(out, 0);
    WriteLE32(out, imageSize);
    WriteLE32(out, 0);
    WriteLE32(out, 0);
    WriteLE32(out, 0);
    WriteLE32(out, 0);

    std::vector<unsigned char> row(static_cast<size_t>(rowSize), 0);
    for (int y = totalHeight - 1; y >= 0; --y)
    {
        const melonDS::u32* src = nullptr;
        int srcY = 0;
        if (y < height)
        {
            src = top;
            srcY = y;
        }
        else
        {
            src = bottom;
            srcY = y - height;
        }

        unsigned char* dst = row.data();
        const melonDS::u32* rowPixels = src + (srcY * width);
        for (int x = 0; x < width; ++x)
        {
            melonDS::u32 pixel = rowPixels[x];
            *dst++ = static_cast<unsigned char>(pixel & 0xFF);
            *dst++ = static_cast<unsigned char>((pixel >> 8) & 0xFF);
            *dst++ = static_cast<unsigned char>((pixel >> 16) & 0xFF);
        }
        out.write(reinterpret_cast<const char*>(row.data()), rowSize);
    }

    return out.good();
}

} // namespace

int main(int argc, char** argv)
{
    Options opts = ParseArgs(argc, argv);
    if (opts.showHelp)
    {
        PrintUsage(argv[0]);
        return 0;
    }
    if (opts.romPath.empty())
    {
        PrintUsage(argv[0]);
        return 1;
    }

    fs::path exePath = fs::absolute(argv[0]);
    melonDS::Platform::Headless_SetLocalBasePath(exePath.parent_path());

    if (opts.savePath.empty())
        opts.savePath = DefaultSavePath(opts.romPath);

    melonDS::Platform::Headless_SetNDSSavePath(opts.savePath);

    std::unique_ptr<melonDS::u8[]> romData;
    std::uint32_t romLen = 0;
    if (!LoadFile(opts.romPath, romData, romLen))
    {
        std::fprintf(stderr, "Failed to load ROM: %s\n", opts.romPath.c_str());
        return 1;
    }

    std::unique_ptr<melonDS::u8[]> saveData;
    std::uint32_t saveLen = 0;
    if (fs::exists(opts.savePath))
    {
        LoadFile(opts.savePath, saveData, saveLen);
    }

    melonDS::NDSCart::NDSCartArgs cartArgs{
        .SDCard = std::nullopt,
        .SRAM = std::move(saveData),
        .SRAMLength = saveLen,
    };

    melonDS::NDSArgs ndsArgs;
    auto nds = std::make_unique<melonDS::NDS>(std::move(ndsArgs), nullptr);

    auto cart = melonDS::NDSCart::ParseROM(std::move(romData), romLen, nullptr, std::move(cartArgs));
    if (!cart)
    {
        std::fprintf(stderr, "Failed to parse ROM: %s\n", opts.romPath.c_str());
        return 1;
    }

    nds->SetNDSCart(std::move(cart));
    nds->Reset();

    fs::path romPath(opts.romPath);
    if (opts.directBoot || nds->NeedsDirectBoot())
    {
        nds->SetupDirectBoot(romPath.filename().string());
    }

    nds->Start();

    melonDS::Headless::Input input;
    for (std::uint32_t frame = 0; frame < opts.frames; ++frame)
    {
        input.Apply(*nds);
        nds->RunFrame();
        if (melonDS::Platform::Headless_StopRequested())
            break;
    }

    if (!opts.screenshotPath.empty())
    {
        const int front = nds->GPU.FrontBuffer;
        const auto* top = nds->GPU.Framebuffer[front][0].get();
        const auto* bottom = nds->GPU.Framebuffer[front][1].get();
        if (!top || !bottom)
        {
            std::fprintf(stderr, "Screenshot failed: framebuffer not ready\n");
        }
        else if (!WriteBMP(opts.screenshotPath, top, bottom, 256, 192))
        {
            std::fprintf(stderr, "Screenshot failed: could not write %s\n", opts.screenshotPath.c_str());
        }
    }

    return 0;
}
