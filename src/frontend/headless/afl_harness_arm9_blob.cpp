#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#include <ctime>
#include <limits>
#include <string>

#if defined(__SANITIZE_MEMORY__)
#include <sanitizer/msan_interface.h>
extern "C" char **environ;
#endif

#include "Args.h"
#include "MemConstants.h"
#include "ARMJIT_Memory.h"
#include "NDS.h"
#include "NDSCart.h"
#include "Savestate.h"

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
constexpr std::uint32_t kPersistentIterations = 1000;
constexpr std::uint32_t kDeterministicRngSeed = 0x4A1F2B3C;
constexpr std::uint32_t kDefaultTimeLimitMs = 10;
constexpr std::uint64_t kDefaultCyclesPerMs = 67000;
constexpr std::uint64_t kTimingSliceCycles = 200000;
}

struct HarnessArgs
{
    std::string baseRomPath;
    std::string timingInputPath;
    bool timingMode = false;
    std::uint32_t timeoutMs = kDefaultTimeLimitMs;
    std::uint64_t cycleLimit = 0;
    std::uint64_t cyclesPerMs = kDefaultCyclesPerMs;
    bool profileSteps = false;
};

static std::uint64_t GetCpuTimeNs()
{
    timespec ts {};
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0)
        return 0;
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull
        + static_cast<std::uint64_t>(ts.tv_nsec);
}

static const char* StopReasonName(melonDS::Platform::StopReason reason)
{
    switch (reason)
    {
        case melonDS::Platform::StopReason::External:
            return "External";
        case melonDS::Platform::StopReason::PowerOff:
            return "PowerOff";
        case melonDS::Platform::StopReason::GBAModeNotSupported:
            return "GBAModeNotSupported";
        case melonDS::Platform::StopReason::BadExceptionRegion:
            return "BadExceptionRegion";
        default:
            return "Unknown";
    }
}

static bool ParseTimeoutMs(const char* value, std::uint32_t& out)
{
    if (!value || !*value)
        return false;
    char* end = nullptr;
    unsigned long parsed = std::strtoul(value, &end, 10);
    if (!end || *end != '\0' || parsed == 0 || parsed > 60000ul)
        return false;
    out = static_cast<std::uint32_t>(parsed);
    return true;
}

static bool ParseUint64(const char* value, std::uint64_t& out)
{
    if (!value || !*value)
        return false;
    char* end = nullptr;
    unsigned long long parsed = std::strtoull(value, &end, 10);
    if (!end || *end != '\0' || parsed == 0)
        return false;
    out = static_cast<std::uint64_t>(parsed);
    return true;
}

static void PrintUsage(const char* argv0)
{
    std::fprintf(stderr,
        "Usage: %s <base_rom.nds> [--time-limit-ms N] [--cycles-per-ms N] [--cycle-limit N] [--timing <arm9_blob.bin>]\n",
        argv0);
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
                std::fprintf(stderr, "--timing requires an input blob path.\n");
                return false;
            }
            out.timingMode = true;
            out.timingInputPath = argv[++i];
            continue;
        }
        if (std::strcmp(arg, "--time-limit-ms") == 0)
        {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "--time-limit-ms requires a value.\n");
                return false;
            }
            if (!ParseTimeoutMs(argv[++i], out.timeoutMs))
            {
                std::fprintf(stderr, "Invalid --time-limit-ms value.\n");
                return false;
            }
            continue;
        }
        if (std::strcmp(arg, "--cycle-limit") == 0)
        {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "--cycle-limit requires a value.\n");
                return false;
            }
            if (!ParseUint64(argv[++i], out.cycleLimit))
            {
                std::fprintf(stderr, "Invalid --cycle-limit value.\n");
                return false;
            }
            continue;
        }
        if (std::strcmp(arg, "--cycles-per-ms") == 0)
        {
            if (i + 1 >= argc)
            {
                std::fprintf(stderr, "--cycles-per-ms requires a value.\n");
                return false;
            }
            if (!ParseUint64(argv[++i], out.cyclesPerMs))
            {
                std::fprintf(stderr, "Invalid --cycles-per-ms value.\n");
                return false;
            }
            continue;
        }
        if (std::strcmp(arg, "--profile-steps") == 0)
        {
            out.profileSteps = true;
            continue;
        }
        if (arg[0] == '-')
        {
            std::fprintf(stderr, "Unknown option: %s\n", arg);
            return false;
        }
        if (out.baseRomPath.empty())
        {
            out.baseRomPath = arg;
            continue;
        }
        std::fprintf(stderr, "Unexpected argument: %s\n", arg);
        return false;
    }

    if (out.baseRomPath.empty())
    {
        PrintUsage(argv[0]);
        return false;
    }

    if (out.timingMode && out.timingInputPath.empty())
    {
        std::fprintf(stderr, "Timing mode requires an ARM9 blob input.\n");
        return false;
    }

    return true;
}

static bool ReadFile(const std::string& path, std::vector<melonDS::u8>& out)
{
    std::ifstream file(path.c_str(), std::ios::binary | std::ios::ate);
    if (!file)
        return false;

    std::streamsize size = file.tellg();
    if (size <= 0)
        return false;

    out.resize(static_cast<size_t>(size));
    file.seekg(0, std::ios::beg);
    if (!file.read(reinterpret_cast<char*>(out.data()), size))
        return false;

    return true;
}

static std::string Basename(const std::string& path)
{
    if (path.empty())
        return path;
    std::size_t sep = path.find_last_of("/\\");
    if (sep == std::string::npos)
        return path;
    if (sep + 1 >= path.size())
        return std::string(".");
    return path.substr(sep + 1);
}

static bool WriteArm9Blob(melonDS::NDS& nds, const melonDS::NDSHeader& header,
    const unsigned char* data, std::uint32_t len, bool invalidate_jit)
{
    if (!data || len == 0 || header.ARM9Size == 0)
        return false;

    std::uint32_t dest_addr = header.ARM9RAMAddress;

    if (dest_addr < nds.ARM9.ITCMSize)
    {
        std::uint32_t offset = dest_addr & (melonDS::ITCMPhysicalSize - 1);
        std::uint32_t capacity = nds.ARM9.ITCMSize - dest_addr;
        std::uint32_t max_len = std::min(header.ARM9Size, capacity);
        std::uint32_t copy_len = std::min(len, max_len);
        std::memcpy(&nds.ARM9.ITCM[offset], data, copy_len);
        if (copy_len < max_len)
            std::memset(&nds.ARM9.ITCM[offset + copy_len], 0, max_len - copy_len);
        if (invalidate_jit)
            nds.JIT.CheckAndInvalidateITCM();
        return true;
    }

    if ((dest_addr & 0xFF000000) == 0x02000000)
    {
        std::uint32_t offset = dest_addr & nds.MainRAMMask;
        std::uint32_t capacity = nds.MainRAMMask + 1 - offset;
        std::uint32_t max_len = std::min(header.ARM9Size, capacity);
        std::uint32_t copy_len = std::min(len, max_len);
        std::memcpy(&nds.MainRAM[offset], data, copy_len);
        if (copy_len < max_len)
            std::memset(&nds.MainRAM[offset + copy_len], 0, max_len - copy_len);
        if (invalidate_jit)
        {
            const std::uint32_t end = dest_addr + max_len;
            for (std::uint32_t addr = dest_addr; addr < end; addr += 16)
                nds.JIT.CheckAndInvalidate<0, melonDS::ARMJIT_Memory::memregion_MainRAM>(addr);
        }
        return true;
    }

    if ((dest_addr & 0xFF000000) == 0x03000000 && nds.SWRAM_ARM9.Mem)
    {
        std::uint32_t offset = dest_addr & nds.SWRAM_ARM9.Mask;
        std::uint32_t capacity = nds.SWRAM_ARM9.Mask + 1 - offset;
        std::uint32_t max_len = std::min(header.ARM9Size, capacity);
        std::uint32_t copy_len = std::min(len, max_len);
        std::memcpy(&nds.SWRAM_ARM9.Mem[offset], data, copy_len);
        if (copy_len < max_len)
            std::memset(&nds.SWRAM_ARM9.Mem[offset + copy_len], 0, max_len - copy_len);
        if (invalidate_jit)
        {
            const std::uint32_t end = dest_addr + max_len;
            for (std::uint32_t addr = dest_addr; addr < end; addr += 16)
                nds.JIT.CheckAndInvalidate<0, melonDS::ARMJIT_Memory::memregion_SharedWRAM>(addr);
        }
        return true;
    }

    return false;
}

int main(int argc, char** argv)
{
#if defined(__SANITIZE_MEMORY__)
    constexpr std::size_t kMaxArgLen = 4096;
    if (argv)
    {
        for (int i = 0; i < argc; i++)
        {
            if (argv[i])
                __msan_unpoison(argv[i], kMaxArgLen);
        }
    }
    if (environ)
    {
        for (char **env = environ; *env; ++env)
            __msan_unpoison(*env, kMaxArgLen);
    }
#endif
    HarnessArgs args{};
    if (!ParseArgs(argc, argv, args))
        return 1;

    std::string baseRomPath = args.baseRomPath;
    std::string timingInputPath = args.timingInputPath;
#if !defined(__SANITIZE_MEMORY__)
    const char* exeArg = (argv && argv[0]) ? argv[0] : "";
    std::string exeStr(exeArg);
    std::string exeDir = [&]() -> std::string {
        std::size_t sep = exeStr.find_last_of("/\\");
        if (sep == std::string::npos)
            return ".";
        std::size_t len = (sep == 0) ? 1 : sep;
        return exeStr.substr(0, len);
    }();
    melonDS::Platform::Headless_SetLocalBasePath(fs::path(exeDir));
#endif
    const std::string baseRomName = Basename(baseRomPath);

    std::vector<melonDS::u8> romData;
    if (!ReadFile(baseRomPath, romData))
    {
        std::fprintf(stderr, "Failed to read base ROM: %s\n", baseRomPath.c_str());
        return 1;
    }

    auto romBuf = std::make_unique<melonDS::u8[]>(romData.size());
    std::memcpy(romBuf.get(), romData.data(), romData.size());

    melonDS::NDSCart::NDSCartArgs cartArgs{};
    auto cart = melonDS::NDSCart::ParseROM(std::move(romBuf), static_cast<melonDS::u32>(romData.size()), nullptr, std::move(cartArgs));
    if (!cart)
    {
        std::fprintf(stderr, "Failed to parse base ROM: %s\n", baseRomPath.c_str());
        return 1;
    }

    const melonDS::NDSHeader header = cart->GetHeader();
    const std::uint32_t maxInputSize = std::min<std::uint32_t>(header.ARM9Size, kMaxInputSize);
    if (maxInputSize == 0)
    {
        std::fprintf(stderr, "Base ROM has empty ARM9 segment.\n");
        return 1;
    }

    melonDS::NDSArgs ndsArgs;
    ndsArgs.JIT = melonDS::JITArgs();
    auto nds = std::make_unique<melonDS::NDS>(std::move(ndsArgs), nullptr);
    nds->SetNDSCart(std::move(cart));
    nds->Reset();
    nds->SetupDirectBoot(baseRomName);
    nds->Start();

    melonDS::Savestate baseState;
    if (!nds->DoSavestate(&baseState) || baseState.Error)
    {
        std::fprintf(stderr, "Failed to create base savestate.\n");
        return 1;
    }
    baseState.Finish();

    melonDS::Platform::Headless_SuppressWarnOnce(true);

    auto* baseBuf = static_cast<melonDS::u8*>(baseState.Buffer());
    const melonDS::u32 baseLen = baseState.Length();

    __AFL_FUZZ_INIT();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif
    if (args.cycleLimit == 0)
    {
        if (args.cyclesPerMs == 0)
        {
            std::fprintf(stderr, "cycles-per-ms must be > 0.\n");
            return 1;
        }
        args.cycleLimit = static_cast<std::uint64_t>(args.timeoutMs) * args.cyclesPerMs;
        if (args.cycleLimit == 0)
        {
            std::fprintf(stderr, "cycle-limit must be > 0.\n");
            return 1;
        }
    }
    const std::uint64_t cycleLimit = args.cycleLimit;

    auto runOnce = [&](const unsigned char* data, std::uint32_t len, bool reportTiming) -> bool
    {
        const std::uint64_t total_start_ns = reportTiming ? GetCpuTimeNs() : 0;
        melonDS::Savestate loadState(baseBuf, baseLen, false);
        if (!nds->DoSavestate(&loadState) || loadState.Error)
            return false;
        const std::uint64_t after_savestate_ns = reportTiming ? GetCpuTimeNs() : 0;

        // Savestate doesn't serialize KeyInput yet; force deterministic baseline.
        nds->KeyInput = 0x007F03FF;

        melonDS::Platform::Headless_ResetStop();
        const std::uint64_t after_reset_ns = reportTiming ? GetCpuTimeNs() : 0;
        nds->Start();

        // JIT cache reset already invalidates blocks; skip per-region invalidation.
        if (!WriteArm9Blob(*nds, header, data, len, false))
            return false;
        const std::uint64_t after_write_ns = reportTiming ? GetCpuTimeNs() : 0;

        nds->ARM9.RNGSeed = kDeterministicRngSeed;
        nds->ARM9.JumpTo(header.ARM9EntryAddress);

        melonDS::NDS::Current = nds.get();
        nds->CurCPU = 0;

        volatile std::uint64_t start_ns = 0;
        volatile std::uint64_t end_ns = 0;
        const std::uint64_t start_cycles = nds->ARM9Timestamp;
        const std::uint64_t max_target = std::numeric_limits<decltype(nds->ARM9Target)>::max();

        if (reportTiming)
            start_ns = GetCpuTimeNs();

        std::uint64_t cycles_run = 0;
        bool stop_requested = false;
        melonDS::Platform::StopReason stop_reason = melonDS::Platform::StopReason::Unknown;
        if (reportTiming)
        {
            while (cycles_run < cycleLimit)
            {
                std::uint64_t target = start_cycles + std::min<std::uint64_t>(cycleLimit, cycles_run + kTimingSliceCycles);
                if (target < start_cycles || target > max_target)
                    target = max_target;
                nds->ARM9Target = target;
                nds->ARM9.Execute<melonDS::CPUExecuteMode::JIT>();
                cycles_run = nds->ARM9Timestamp - start_cycles;
                if (melonDS::Platform::Headless_StopRequested())
                {
                    stop_requested = true;
                    stop_reason = melonDS::Platform::Headless_StopReason();
                    break;
                }
                if (target == max_target)
                    break;
            }
        }
        else
        {
            std::uint64_t target = start_cycles + cycleLimit;
            if (target < start_cycles || target > max_target)
                target = max_target;
            nds->ARM9Target = target;
            nds->ARM9.Execute<melonDS::CPUExecuteMode::JIT>();
            cycles_run = nds->ARM9Timestamp - start_cycles;
            if (melonDS::Platform::Headless_StopRequested())
            {
                stop_requested = true;
                stop_reason = melonDS::Platform::Headless_StopReason();
            }
        }

        if (reportTiming)
            end_ns = GetCpuTimeNs();

        if (reportTiming)
        {
            double cpu_ms = static_cast<double>(end_ns - start_ns) / 1e6;
            std::printf("timing: cpu_ms=%.3f cycles=%llu cycle_limit=%llu timeout_ms=%u input_len=%u\n",
                cpu_ms,
                static_cast<unsigned long long>(cycles_run),
                static_cast<unsigned long long>(cycleLimit),
                args.timeoutMs,
                len);
            if (stop_requested)
                std::fprintf(stderr, "stop: reason=%s\n", StopReasonName(stop_reason));
            if (args.profileSteps)
            {
                const double savestate_ms = static_cast<double>(after_savestate_ns - total_start_ns) / 1e6;
                const double reset_ms = static_cast<double>(after_reset_ns - after_savestate_ns) / 1e6;
                const double prep_ms = static_cast<double>(after_write_ns - after_reset_ns) / 1e6;
                const double exec_ms = static_cast<double>(end_ns - start_ns) / 1e6;
                const double total_ms = static_cast<double>(end_ns - total_start_ns) / 1e6;
                std::printf("profile: savestate_ms=%.3f reset_ms=%.3f prep_ms=%.3f exec_ms=%.3f total_ms=%.3f\n",
                    savestate_ms, reset_ms, prep_ms, exec_ms, total_ms);
            }
            std::fflush(stdout);
        }

        return true;
    };

    if (args.timingMode)
    {
        std::vector<melonDS::u8> inputData;
        if (!ReadFile(timingInputPath, inputData))
        {
            std::fprintf(stderr, "Failed to read ARM9 blob: %s\n", timingInputPath.c_str());
            return 1;
        }
        if (inputData.empty())
        {
            std::fprintf(stderr, "ARM9 blob is empty: %s\n", timingInputPath.c_str());
            return 1;
        }
        std::uint32_t len = static_cast<std::uint32_t>(std::min<std::size_t>(inputData.size(), maxInputSize));
        if (!runOnce(inputData.data(), len, true))
            return 1;
        return 0;
    }

    unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(kPersistentIterations))
    {
        const ssize_t signed_len = __AFL_FUZZ_TESTCASE_LEN;
        if (signed_len <= 0)
            continue;
        std::uint32_t len = static_cast<std::uint32_t>(signed_len);
        if (len > maxInputSize)
            len = maxInputSize;

        if (!runOnce(buf, len, false))
            return 1;
    }

    return 0;
}
