#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <vector>
#include <csignal>
#include <csetjmp>
#include <sys/time.h>

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
constexpr std::uint32_t kRunTimeoutMs = 5;
constexpr std::uint32_t kTimeSliceSysCycles = 2048;
}

namespace {
sigjmp_buf gTimeoutJmp;
volatile sig_atomic_t gTimeoutActive = 0;

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
}

void ArmTimeoutTimer()
{
    struct itimerval timer {};
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = static_cast<suseconds_t>(kRunTimeoutMs) * 1000;
    setitimer(ITIMER_VIRTUAL, &timer, nullptr);
}

void DisarmTimeoutTimer()
{
    struct itimerval timer {};
    setitimer(ITIMER_VIRTUAL, &timer, nullptr);
}
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
    if (argc < 2)
    {
        std::fprintf(stderr, "Usage: %s <base_rom.nds>\n", argv[0]);
        return 1;
    }

    fs::path exePath = fs::absolute(argv[0]);
    fs::path baseRomPath = fs::absolute(argv[1]);
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

    unsigned char* buf = __AFL_FUZZ_TESTCASE_BUF;
    while (__AFL_LOOP(kPersistentIterations))
    {
        const ssize_t signed_len = __AFL_FUZZ_TESTCASE_LEN;
        if (signed_len <= 0)
            continue;
        std::uint32_t len = static_cast<std::uint32_t>(signed_len);
        if (len > maxInputSize)
            len = maxInputSize;

        melonDS::Savestate loadState(baseBuf, baseLen, false);
        if (!nds->DoSavestate(&loadState) || loadState.Error)
            continue;

        nds->Start();

        if (!WriteArm9Blob(*nds, header, buf, len))
            continue;

        nds->ARM9.RNGSeed = kDeterministicRngSeed;
        nds->ARM9.JumpTo(header.ARM9EntryAddress);

        melonDS::NDS::Current = nds.get();
        nds->CurCPU = 0;

        gTimeoutActive = 1;
        if (sigsetjmp(gTimeoutJmp, 1) == 0)
        {
            ArmTimeoutTimer();
            const std::uint64_t slice_ticks = static_cast<std::uint64_t>(kTimeSliceSysCycles) << nds->ARM9ClockShift;
            nds->ARM9Target = nds->ARM9Timestamp + slice_ticks;
            nds->ARM9.Execute<melonDS::CPUExecuteMode::JIT>();
        }
        gTimeoutActive = 0;
        DisarmTimeoutTimer();
    }

    return 0;
}
