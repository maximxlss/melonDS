#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>

#include "Args.h"
#include "NDS.h"
#include "NDSCart.h"

#include "HeadlessPlatform.h"
#include "Platform.h"

#ifndef __AFL_FUZZ_INIT
#include <unistd.h>
#define __AFL_FUZZ_INIT() \
    do { } while (0)
#define __AFL_LOOP(x) ((fuzz_len = read(0, fuzz_buf, sizeof(fuzz_buf))) > 0)
static unsigned char fuzz_buf[1024 * 1024];
static ssize_t fuzz_len = 0;
#define __AFL_FUZZ_TESTCASE_BUF fuzz_buf
#define __AFL_FUZZ_TESTCASE_LEN fuzz_len
#define __AFL_INIT() \
    do { } while (0)
#endif

namespace fs = std::filesystem;

namespace {
constexpr std::uint32_t kMaxInputSize = 16 * 1024 * 1024;
constexpr std::uint32_t kPersistentIterations = 100;
}

struct HarnessArgs
{
    fs::path timingRomPath;
    bool timingMode = false;
};

static std::uint64_t GetCpuTimeNs()
{
    timespec ts {};
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0)
        return 0;
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull
        + static_cast<std::uint64_t>(ts.tv_nsec);
}

static void PrintUsage(const char* argv0)
{
    std::fprintf(stderr, "Usage: %s [--timing <rom.nds>]\n", argv0);
}

static bool ParseArgs(int argc, char** argv, HarnessArgs& out)
{
    for (int i = 1; i < argc; i++)
    {
        const char* arg = argv[i];
        if (std::strcmp(arg, "--help") == 0)
        {
            PrintUsage(argv[0]);
            return false;
        }
        if (std::strcmp(arg, "--timing") == 0)
        {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "--timing requires a ROM path.\n");
                return false;
            }
            out.timingMode = true;
            out.timingRomPath = fs::absolute(argv[++i]);
            continue;
        }
        std::fprintf(stderr, "Unknown option: %s\n", arg);
        return false;
    }

    return true;
}

int main(int argc, char** argv)
{
    HarnessArgs args;
    if (!ParseArgs(argc, argv, args))
        return 1;

    fs::path exePath = fs::absolute(argv[0]);
    melonDS::Platform::Headless_SetLocalBasePath(exePath.parent_path());

    __AFL_FUZZ_INIT();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    if (args.timingMode)
    {
        std::vector<melonDS::u8> romData;
        {
            std::ifstream file(args.timingRomPath, std::ios::binary | std::ios::ate);
            if (!file)
            {
                std::fprintf(stderr, "Failed to read ROM: %s\n", args.timingRomPath.string().c_str());
                return 1;
            }
            std::streamsize size = file.tellg();
            if (size <= 0 || static_cast<std::uint64_t>(size) > kMaxInputSize)
            {
                std::fprintf(stderr, "ROM size invalid: %s\n", args.timingRomPath.string().c_str());
                return 1;
            }
            romData.resize(static_cast<size_t>(size));
            file.seekg(0, std::ios::beg);
            if (!file.read(reinterpret_cast<char*>(romData.data()), size))
            {
                std::fprintf(stderr, "Failed to read ROM: %s\n", args.timingRomPath.string().c_str());
                return 1;
            }
        }

        auto romBuf = std::make_unique<melonDS::u8[]>(romData.size());
        std::memcpy(romBuf.get(), romData.data(), romData.size());

        melonDS::NDSCart::NDSCartArgs cartArgs{};
        auto cart = melonDS::NDSCart::ParseROM(std::move(romBuf), static_cast<melonDS::u32>(romData.size()), nullptr, std::move(cartArgs));
        if (!cart)
        {
            std::fprintf(stderr, "Failed to parse ROM: %s\n", args.timingRomPath.string().c_str());
            return 1;
        }

        melonDS::NDSArgs ndsArgs;
        auto nds = std::make_unique<melonDS::NDS>(std::move(ndsArgs), nullptr);
        nds->SetNDSCart(std::move(cart));
        nds->Reset();
        nds->SetupDirectBoot(args.timingRomPath.filename().string());
        nds->Start();

        std::uint64_t start_ns = GetCpuTimeNs();
        nds->RunFrame();
        std::uint64_t end_ns = GetCpuTimeNs();

        double cpu_ms = static_cast<double>(end_ns - start_ns) / 1e6;
        std::printf("timing: cpu_ms=%.3f\n", cpu_ms);
        std::fflush(stdout);
        return 0;
    }

    unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(kPersistentIterations))
    {
        const ssize_t signed_len = __AFL_FUZZ_TESTCASE_LEN;
        if (signed_len <= 0)
            continue;
        std::uint32_t len = static_cast<std::uint32_t>(signed_len);
        if (len > kMaxInputSize)
            continue;

        auto romData = std::make_unique<melonDS::u8[]>(len);
        std::memcpy(romData.get(), buf, len);

        melonDS::NDSCart::NDSCartArgs cartArgs{};
        auto cart = melonDS::NDSCart::ParseROM(std::move(romData), len, nullptr, std::move(cartArgs));
        if (!cart)
            continue;

        melonDS::NDSArgs ndsArgs;
        auto nds = std::make_unique<melonDS::NDS>(std::move(ndsArgs), nullptr);
        nds->SetNDSCart(std::move(cart));
        nds->Reset();
        nds->SetupDirectBoot("fuzz.nds");
        nds->Start();
        nds->RunFrame();
    }

    return 0;
}
