#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#include <csignal>
#include <csetjmp>
#include <ctime>
#include <limits>
#include <time.h>

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
constexpr std::uint32_t kRunTimeoutMs = 2;
}

namespace {
sigjmp_buf gTimeoutJmp;
volatile sig_atomic_t gTimeoutActive = 0;
std::uint32_t gRunTimeoutMs = kRunTimeoutMs;
timer_t gThreadTimer = {};
bool gThreadTimerReady = false;

void TimeoutHandler(int)
{
    if (!gTimeoutActive)
        return;
    siglongjmp(gTimeoutJmp, 1);
}

void InstallTimeoutHandler()
{
    static bool installed = false;
    if (installed)
        return;
    installed = true;

    struct sigaction sa {};
    sa.sa_handler = TimeoutHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    sigaction(SIGVTALRM, &sa, nullptr);

    sigevent sev {};
    sev.sigev_notify = SIGEV_SIGNAL;
    sev.sigev_signo = SIGVTALRM;
    if (timer_create(CLOCK_THREAD_CPUTIME_ID, &sev, &gThreadTimer) != 0)
    {
        std::perror("timer_create");
        std::exit(1);
    }
    gThreadTimerReady = true;
}

void ArmTimeoutTimer()
{
    if (!gThreadTimerReady)
        return;
    itimerspec timer {};
    timer.it_value.tv_sec = gRunTimeoutMs / 1000u;
    timer.it_value.tv_nsec = static_cast<long>(gRunTimeoutMs % 1000u) * 1000000L;
    timer_settime(gThreadTimer, 0, &timer, nullptr);
}

void DisarmTimeoutTimer()
{
    if (!gThreadTimerReady)
        return;
    itimerspec timer {};
    timer_settime(gThreadTimer, 0, &timer, nullptr);
}
}

struct HarnessArgs
{
    fs::path baseRomPath;
    fs::path timingInputPath;
    bool timingMode = false;
    std::uint32_t timeoutMs = kRunTimeoutMs;
};

static std::uint64_t GetCpuTimeNs()
{
    timespec ts {};
    if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts) != 0)
        return 0;
    return static_cast<std::uint64_t>(ts.tv_sec) * 1000000000ull
        + static_cast<std::uint64_t>(ts.tv_nsec);
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

static void PrintUsage(const char* argv0)
{
    std::fprintf(stderr,
        "Usage: %s <base_rom.nds> [--time-limit-ms N] [--timing <arm9_blob.bin>]\n",
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
            out.timingInputPath = fs::absolute(argv[++i]);
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
        if (arg[0] == '-')
        {
            std::fprintf(stderr, "Unknown option: %s\n", arg);
            return false;
        }
        if (out.baseRomPath.empty())
        {
            out.baseRomPath = fs::absolute(arg);
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

static bool ReadFile(const fs::path& path, std::vector<melonDS::u8>& out)
{
    std::ifstream file(path, std::ios::binary | std::ios::ate);
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

static bool WriteArm9Blob(melonDS::NDS& nds, const melonDS::NDSHeader& header,
    const unsigned char* data, std::uint32_t len)
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
        const std::uint32_t end = dest_addr + max_len;
        for (std::uint32_t addr = dest_addr; addr < end; addr += 16)
            nds.JIT.CheckAndInvalidate<0, melonDS::ARMJIT_Memory::memregion_MainRAM>(addr);
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
        const std::uint32_t end = dest_addr + max_len;
        for (std::uint32_t addr = dest_addr; addr < end; addr += 16)
            nds.JIT.CheckAndInvalidate<0, melonDS::ARMJIT_Memory::memregion_SharedWRAM>(addr);
        return true;
    }

    return false;
}

int main(int argc, char** argv)
{
    HarnessArgs args;
    if (!ParseArgs(argc, argv, args))
        return 1;

    gRunTimeoutMs = args.timeoutMs;

    fs::path exePath = fs::absolute(argv[0]);
    fs::path baseRomPath = args.baseRomPath;
    melonDS::Platform::Headless_SetLocalBasePath(exePath.parent_path());

    std::vector<melonDS::u8> romData;
    if (!ReadFile(baseRomPath, romData))
    {
        std::fprintf(stderr, "Failed to read base ROM: %s\n", baseRomPath.string().c_str());
        return 1;
    }

    auto romBuf = std::make_unique<melonDS::u8[]>(romData.size());
    std::memcpy(romBuf.get(), romData.data(), romData.size());

    melonDS::NDSCart::NDSCartArgs cartArgs{};
    auto cart = melonDS::NDSCart::ParseROM(std::move(romBuf), static_cast<melonDS::u32>(romData.size()), nullptr, std::move(cartArgs));
    if (!cart)
    {
        std::fprintf(stderr, "Failed to parse base ROM: %s\n", baseRomPath.string().c_str());
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
    nds->SetupDirectBoot(baseRomPath.filename().string());
    nds->Start();

    melonDS::Savestate baseState;
    if (!nds->DoSavestate(&baseState) || baseState.Error)
    {
        std::fprintf(stderr, "Failed to create base savestate.\n");
        return 1;
    }
    baseState.Finish();

    auto* baseBuf = static_cast<melonDS::u8*>(baseState.Buffer());
    const melonDS::u32 baseLen = baseState.Length();

    __AFL_FUZZ_INIT();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

    InstallTimeoutHandler();

    auto runOnce = [&](const unsigned char* data, std::uint32_t len, bool reportTiming) -> bool
    {
        melonDS::Savestate loadState(baseBuf, baseLen, false);
        if (!nds->DoSavestate(&loadState) || loadState.Error)
            return false;

        nds->JIT.ResetBlockCache();
        nds->Start();

        if (!WriteArm9Blob(*nds, header, data, len))
            return false;

        nds->ARM9.RNGSeed = kDeterministicRngSeed;
        nds->ARM9.JumpTo(header.ARM9EntryAddress);

        melonDS::NDS::Current = nds.get();
        nds->CurCPU = 0;

        volatile std::uint64_t start_ns = 0;
        volatile std::uint64_t end_ns = 0;
        gTimeoutActive = 1;
        int jumped = sigsetjmp(gTimeoutJmp, 1);
        if (jumped == 0)
        {
            nds->ARM9Target = std::numeric_limits<decltype(nds->ARM9Target)>::max();
            if (reportTiming)
                start_ns = GetCpuTimeNs();
            ArmTimeoutTimer();
            nds->ARM9.Execute<melonDS::CPUExecuteMode::JIT>();
            if (reportTiming)
                end_ns = GetCpuTimeNs();
        }
        gTimeoutActive = 0;
        DisarmTimeoutTimer();

        if (reportTiming)
        {
            if (jumped != 0)
                end_ns = GetCpuTimeNs();
            double cpu_ms = static_cast<double>(end_ns - start_ns) / 1e6;
            std::printf("timing: cpu_ms=%.3f timed_out=%d timeout_ms=%u input_len=%u\n",
                cpu_ms, jumped != 0 ? 1 : 0, gRunTimeoutMs, len);
            std::fflush(stdout);
        }

        return true;
    };

    if (args.timingMode)
    {
        std::vector<melonDS::u8> inputData;
        if (!ReadFile(args.timingInputPath, inputData))
        {
            std::fprintf(stderr, "Failed to read ARM9 blob: %s\n", args.timingInputPath.string().c_str());
            return 1;
        }
        if (inputData.empty())
        {
            std::fprintf(stderr, "ARM9 blob is empty: %s\n", args.timingInputPath.string().c_str());
            return 1;
        }
        std::uint32_t len = static_cast<std::uint32_t>(std::min<std::size_t>(inputData.size(), maxInputSize));
        runOnce(inputData.data(), len, true);
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

        runOnce(buf, len, false);
    }

    return 0;
}
