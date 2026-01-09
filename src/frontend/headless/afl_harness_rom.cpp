#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
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

int main(int argc, char** argv)
{
    fs::path exePath = fs::absolute(argv[0]);
    melonDS::Platform::Headless_SetLocalBasePath(exePath.parent_path());

    __AFL_FUZZ_INIT();

#ifdef __AFL_HAVE_MANUAL_CONTROL
    __AFL_INIT();
#endif

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
