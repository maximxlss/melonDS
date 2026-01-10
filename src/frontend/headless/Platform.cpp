/*
    Copyright 2016-2025 melonDS team

    This file is part of melonDS.

    melonDS is free software: you can redistribute it and/or modify it under
    the terms of the GNU General Public License as published by the Free
    Software Foundation, either version 3 of the License, or (at your option)
    any later version.

    melonDS is distributed in the hope that it will be useful, but WITHOUT ANY
    WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
    FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with melonDS. If not, see http://www.gnu.org/licenses/.
*/

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <thread>

#ifdef _WIN32
#include <windows.h>
#else
#include <dlfcn.h>
#endif

#include "HeadlessPlatform.h"
#include "Platform.h"
#include "SPI_Firmware.h"
namespace fs = std::filesystem;

namespace melonDS::Platform
{

namespace {

std::mutex g_localPathMutex;
fs::path g_localPath = fs::current_path();

std::mutex g_savePathMutex;
std::string g_ndsSavePath;
std::string g_gbaSavePath;
std::string g_firmwarePath;

std::atomic<bool> g_warnedMp{false};
std::atomic<bool> g_warnedNetSend{false};
std::atomic<bool> g_warnedNetRecv{false};
std::atomic<bool> g_warnedMic{false};

std::atomic<bool> g_stopRequested{false};
std::atomic<StopReason> g_stopReason{StopReason::Unknown};

std::atomic<u32> g_addonKeyMask{0};
std::atomic<float> g_motionValues[6]{};

const auto g_timeStart = std::chrono::steady_clock::now();

constexpr char AccessMode(FileMode mode, bool file_exists)
{
    if (mode & FileMode::Append)
        return 'a';

    if (!(mode & FileMode::Write))
        return 'r';

    if (mode & FileMode::NoCreate)
        return 'r';

    if ((mode & FileMode::Preserve) && file_exists)
        return 'r';

    return 'w';
}

constexpr bool IsExtended(FileMode mode)
{
    return (mode & FileMode::ReadWrite) == FileMode::ReadWrite;
}

std::string GetModeString(FileMode mode, bool file_exists)
{
    std::string modeString;
    modeString += AccessMode(mode, file_exists);

    if (IsExtended(mode))
        modeString += '+';

    if (!(mode & FileMode::Text))
        modeString += 'b';

    return modeString;
}

fs::path ResolveLocalPath(const std::string& filename)
{
    fs::path path = fs::u8path(filename);
    if (path.is_absolute())
        return path;

    std::lock_guard<std::mutex> lock(g_localPathMutex);
    return g_localPath / path;
}

[[noreturn]] void ThrowUnimplemented(const char* feature)
{
    Log(LogLevel::Error, "Headless platform does not implement %s\n", feature);
    throw std::runtime_error(std::string("Headless platform does not implement ") + feature);
}

} // namespace

void Headless_SetLocalBasePath(const fs::path& path)
{
    std::lock_guard<std::mutex> lock(g_localPathMutex);
    g_localPath = path;
}

void Headless_SetNDSSavePath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(g_savePathMutex);
    g_ndsSavePath = path;
}

void Headless_SetGBASavePath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(g_savePathMutex);
    g_gbaSavePath = path;
}

void Headless_SetFirmwarePath(const std::string& path)
{
    std::lock_guard<std::mutex> lock(g_savePathMutex);
    g_firmwarePath = path;
}

bool Headless_StopRequested()
{
    return g_stopRequested.load(std::memory_order_relaxed);
}

StopReason Headless_StopReason()
{
    return g_stopReason.load(std::memory_order_relaxed);
}

void Headless_ResetStop()
{
    g_stopRequested.store(false, std::memory_order_relaxed);
    g_stopReason.store(StopReason::Unknown, std::memory_order_relaxed);
}

void Headless_SuppressWarnOnce(bool suppress)
{
    g_warnedMp.store(suppress, std::memory_order_relaxed);
    g_warnedNetSend.store(suppress, std::memory_order_relaxed);
    g_warnedNetRecv.store(suppress, std::memory_order_relaxed);
    g_warnedMic.store(suppress, std::memory_order_relaxed);
}

void Headless_SetAddonKeyDown(KeyType type, bool down)
{
    u32 mask = 1u << static_cast<u32>(type);
    if (down)
        g_addonKeyMask.fetch_or(mask, std::memory_order_relaxed);
    else
        g_addonKeyMask.fetch_and(~mask, std::memory_order_relaxed);
}

void Headless_SetMotionValue(MotionQueryType type, float value)
{
    g_motionValues[type].store(value, std::memory_order_relaxed);
}

void SignalStop(StopReason reason, void* userdata)
{
    (void)userdata;
    g_stopRequested.store(true, std::memory_order_relaxed);
    g_stopReason.store(reason, std::memory_order_relaxed);
}


std::string GetLocalFilePath(const std::string& filename)
{
    return ResolveLocalPath(filename).string();
}

FileHandle* OpenFile(const std::string& path, FileMode mode)
{
    if ((mode & (FileMode::ReadWrite | FileMode::Append)) == FileMode::None)
    {
        Log(LogLevel::Error, "Attempted to open \"%s\" in neither read nor write mode (FileMode 0x%x)\n",
            path.c_str(), mode);
        return nullptr;
    }

    fs::path fsPath = fs::u8path(path);
    std::string modeString = GetModeString(mode, fs::exists(fsPath));

#ifdef _WIN32
    std::wstring wmode(modeString.begin(), modeString.end());
    FILE* file = _wfopen(fsPath.wstring().c_str(), wmode.c_str());
#else
    FILE* file = std::fopen(fsPath.string().c_str(), modeString.c_str());
#endif

    if (!file)
    {
        Log(LogLevel::Warn, "Failed to open \"%s\" with FileMode 0x%x (effective mode \"%s\")\n",
            path.c_str(), mode, modeString.c_str());
        return nullptr;
    }
    
    return reinterpret_cast<FileHandle*>(file);
}

FileHandle* OpenLocalFile(const std::string& path, FileMode mode)
{
    return OpenFile(GetLocalFilePath(path), mode);
}

bool CloseFile(FileHandle* file)
{
    return std::fclose(reinterpret_cast<FILE*>(file)) == 0;
}

bool IsEndOfFile(FileHandle* file)
{
    return std::feof(reinterpret_cast<FILE*>(file)) != 0;
}

bool FileReadLine(char* str, int count, FileHandle* file)
{
    return std::fgets(str, count, reinterpret_cast<FILE*>(file)) != nullptr;
}

u64 FilePosition(FileHandle* file)
{
    return static_cast<u64>(std::ftell(reinterpret_cast<FILE*>(file)));
}

bool FileSeek(FileHandle* file, s64 offset, FileSeekOrigin origin)
{
    int stdorigin = SEEK_SET;
    switch (origin)
    {
        case FileSeekOrigin::Start: stdorigin = SEEK_SET; break;
        case FileSeekOrigin::Current: stdorigin = SEEK_CUR; break;
        case FileSeekOrigin::End: stdorigin = SEEK_END; break;
    }

    return std::fseek(reinterpret_cast<FILE*>(file), static_cast<long>(offset), stdorigin) == 0;
}

void FileRewind(FileHandle* file)
{
    std::rewind(reinterpret_cast<FILE*>(file));
}

u64 FileRead(void* data, u64 size, u64 count, FileHandle* file)
{
    return std::fread(data, static_cast<size_t>(size), static_cast<size_t>(count),
        reinterpret_cast<FILE*>(file));
}

bool FileFlush(FileHandle* file)
{
    return std::fflush(reinterpret_cast<FILE*>(file)) == 0;
}

u64 FileWrite(const void* data, u64 size, u64 count, FileHandle* file)
{
    return std::fwrite(data, static_cast<size_t>(size), static_cast<size_t>(count),
        reinterpret_cast<FILE*>(file));
}

u64 FileWriteFormatted(FileHandle* file, const char* fmt, ...)
{
    if (!fmt)
        return 0;

    va_list args;
    va_start(args, fmt);
    u64 ret = std::vfprintf(reinterpret_cast<FILE*>(file), fmt, args);
    va_end(args);
    return ret;
}

u64 FileLength(FileHandle* file)
{
    FILE* stdfile = reinterpret_cast<FILE*>(file);
    long pos = std::ftell(stdfile);
    if (pos < 0)
        return 0;
    if (std::fseek(stdfile, 0, SEEK_END) != 0)
        return 0;
    long len = std::ftell(stdfile);
    std::fseek(stdfile, pos, SEEK_SET);
    if (len < 0)
        return 0;
    return static_cast<u64>(len);
}

bool FileExists(const std::string& name)
{
    return fs::exists(fs::u8path(name));
}

bool LocalFileExists(const std::string& name)
{
    return fs::exists(ResolveLocalPath(name));
}

bool CheckFileWritable(const std::string& filepath)
{
    FileHandle* file = OpenFile(filepath, FileMode::Append);
    if (!file)
        return false;

    CloseFile(file);
    return true;
}

bool CheckLocalFileWritable(const std::string& filepath)
{
    FileHandle* file = OpenLocalFile(filepath, FileMode::Append);
    if (!file)
        return false;

    CloseFile(file);
    return true;
}

void Log(LogLevel level, const char* fmt, ...)
{
    if (!fmt)
        return;

    FILE* out = (level == LogLevel::Error || level == LogLevel::Warn) ? stderr : stdout;
    va_list args;
    va_start(args, fmt);
    std::vfprintf(out, fmt, args);
    va_end(args);
}

struct Thread
{
    std::thread worker;
};

Thread* Thread_Create(std::function<void()> func)
{
    return new Thread{std::thread(std::move(func))};
}

void Thread_Free(Thread* thread)
{
    if (!thread)
        return;

    if (thread->worker.joinable())
        thread->worker.join();
    delete thread;
}

void Thread_Wait(Thread* thread)
{
    if (thread && thread->worker.joinable())
        thread->worker.join();
}

struct Semaphore
{
    std::mutex mutex;
    std::condition_variable cv;
    int count = 0;
};

Semaphore* Semaphore_Create()
{
    return new Semaphore();
}

void Semaphore_Free(Semaphore* sema)
{
    delete sema;
}

void Semaphore_Reset(Semaphore* sema)
{
    std::lock_guard<std::mutex> lock(sema->mutex);
    sema->count = 0;
}

void Semaphore_Wait(Semaphore* sema)
{
    std::unique_lock<std::mutex> lock(sema->mutex);
    sema->cv.wait(lock, [sema]() { return sema->count > 0; });
    --sema->count;
}

bool Semaphore_TryWait(Semaphore* sema, int timeout_ms)
{
    std::unique_lock<std::mutex> lock(sema->mutex);
    if (timeout_ms == 0)
    {
        if (sema->count == 0)
            return false;
    }
    else
    {
        if (!sema->cv.wait_for(lock, std::chrono::milliseconds(timeout_ms),
                [sema]() { return sema->count > 0; }))
        {
            return false;
        }
    }
    --sema->count;
    return true;
}

void Semaphore_Post(Semaphore* sema, int count)
{
    {
        std::lock_guard<std::mutex> lock(sema->mutex);
        sema->count += count;
    }
    sema->cv.notify_all();
}

struct Mutex
{
    std::mutex mutex;
};

Mutex* Mutex_Create()
{
    return new Mutex();
}

void Mutex_Free(Mutex* mutex)
{
    delete mutex;
}

void Mutex_Lock(Mutex* mutex)
{
    mutex->mutex.lock();
}

void Mutex_Unlock(Mutex* mutex)
{
    mutex->mutex.unlock();
}

bool Mutex_TryLock(Mutex* mutex)
{
    return mutex->mutex.try_lock();
}

void Sleep(u64 usecs)
{
    std::this_thread::sleep_for(std::chrono::microseconds(usecs));
}

u64 GetMSCount()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - g_timeStart).count();
}

u64 GetUSCount()
{
    return std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::steady_clock::now() - g_timeStart).count();
}

void WriteNDSSave(const u8* savedata, u32 savelen, u32 writeoffset, u32 writelen, void* userdata)
{
    (void)writeoffset;
    (void)writelen;
    (void)userdata;

    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_savePathMutex);
        path = g_ndsSavePath;
    }

    if (path.empty())
    {
        Log(LogLevel::Warn, "Headless: NDS save requested, but no save path configured\n");
        return;
    }

    FileHandle* file = OpenFile(path, FileMode::Write);
    if (!file)
    {
        Log(LogLevel::Error, "Headless: Failed to open NDS save path \"%s\"\n", path.c_str());
        return;
    }

    FileWrite(savedata, savelen, 1, file);
    CloseFile(file);
}

void WriteGBASave(const u8* savedata, u32 savelen, u32 writeoffset, u32 writelen, void* userdata)
{
    (void)writeoffset;
    (void)writelen;
    (void)userdata;

    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_savePathMutex);
        path = g_gbaSavePath;
    }

    if (path.empty())
    {
        Log(LogLevel::Warn, "Headless: GBA save requested, but no save path configured\n");
        return;
    }

    FileHandle* file = OpenFile(path, FileMode::Write);
    if (!file)
    {
        Log(LogLevel::Error, "Headless: Failed to open GBA save path \"%s\"\n", path.c_str());
        return;
    }

    FileWrite(savedata, savelen, 1, file);
    CloseFile(file);
}

void WriteFirmware(const Firmware& firmware, u32 writeoffset, u32 writelen, void* userdata)
{
    (void)writeoffset;
    (void)writelen;
    (void)userdata;

    std::string path;
    {
        std::lock_guard<std::mutex> lock(g_savePathMutex);
        path = g_firmwarePath;
    }

    if (path.empty())
    {
        Log(LogLevel::Warn, "Headless: Firmware write requested, but no firmware path configured\n");
        return;
    }

    FileHandle* file = OpenFile(path, FileMode::Write);
    if (!file)
    {
        Log(LogLevel::Error, "Headless: Failed to open firmware path \"%s\"\n", path.c_str());
        return;
    }

    FileWrite(firmware.Buffer(), firmware.Length(), 1, file);
    CloseFile(file);
}

void WriteDateTime(int year, int month, int day, int hour, int minute, int second, void* userdata)
{
    (void)userdata;
    Log(LogLevel::Info, "Headless: RTC write requested %04d-%02d-%02d %02d:%02d:%02d\n",
        year, month, day, hour, minute, second);
}

void MP_Begin(void* userdata)
{
    (void)userdata;
    if (!g_warnedMp.exchange(true))
        Log(LogLevel::Error, "Headless: local multiplayer is disabled\n");
}

void MP_End(void* userdata)
{
    (void)userdata;
}

int MP_SendPacket(u8* data, int len, u64 timestamp, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)len;
    (void)timestamp;
    return 0;
}

int MP_RecvPacket(u8* data, u64* timestamp, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)timestamp;
    return 0;
}

int MP_SendCmd(u8* data, int len, u64 timestamp, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)len;
    (void)timestamp;
    return 0;
}

int MP_SendReply(u8* data, int len, u64 timestamp, u16 aid, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)len;
    (void)timestamp;
    (void)aid;
    return 0;
}

int MP_SendAck(u8* data, int len, u64 timestamp, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)len;
    (void)timestamp;
    return 0;
}

int MP_RecvHostPacket(u8* data, u64* timestamp, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)timestamp;
    return 0;
}

u16 MP_RecvReplies(u8* data, u64 timestamp, u16 aidmask, void* userdata)
{
    (void)userdata;
    (void)data;
    (void)timestamp;
    (void)aidmask;
    return 0;
}

int Net_SendPacket(u8* data, int len, void* userdata)
{
    (void)data;
    (void)len;
    (void)userdata;
    if (!g_warnedNetSend.exchange(true))
        Log(LogLevel::Error, "Headless: Wi-Fi/network is disabled; dropping packets\n");
    return 0;
}

int Net_RecvPacket(u8* data, void* userdata)
{
    (void)data;
    (void)userdata;
    if (!g_warnedNetRecv.exchange(true))
        Log(LogLevel::Error, "Headless: Wi-Fi/network is disabled; no packets available\n");
    return 0;
}

void Camera_Start(int num, void* userdata)
{
    (void)num;
    (void)userdata;
    ThrowUnimplemented("camera");
}

void Camera_Stop(int num, void* userdata)
{
    (void)num;
    (void)userdata;
    ThrowUnimplemented("camera");
}

void Camera_CaptureFrame(int num, u32* frame, int width, int height, bool yuv, void* userdata)
{
    (void)num;
    (void)frame;
    (void)width;
    (void)height;
    (void)yuv;
    (void)userdata;
    ThrowUnimplemented("camera");
}

void Mic_Start(void* userdata)
{
    (void)userdata;
    if (!g_warnedMic.exchange(true))
        Log(LogLevel::Error, "Headless: microphone is disabled; returning silence\n");
}

void Mic_Stop(void* userdata)
{
    (void)userdata;
}

int Mic_ReadInput(s16* data, int maxlength, void* userdata)
{
    (void)data;
    (void)maxlength;
    (void)userdata;
    return 0;
}

struct AACDecoder {};

AACDecoder* AAC_Init()
{
    ThrowUnimplemented("AAC decoding");
}

void AAC_DeInit(AACDecoder* dec)
{
    (void)dec;
    ThrowUnimplemented("AAC decoding");
}

bool AAC_Configure(AACDecoder* dec, int frequency, int channels)
{
    (void)dec;
    (void)frequency;
    (void)channels;
    ThrowUnimplemented("AAC decoding");
}

bool AAC_DecodeFrame(AACDecoder* dec, const void* input, int inputlen, void* output, int outputlen)
{
    (void)dec;
    (void)input;
    (void)inputlen;
    (void)output;
    (void)outputlen;
    ThrowUnimplemented("AAC decoding");
}

bool Addon_KeyDown(KeyType type, void* userdata)
{
    (void)userdata;
    u32 mask = 1u << static_cast<u32>(type);
    return (g_addonKeyMask.load(std::memory_order_relaxed) & mask) != 0;
}

void Addon_RumbleStart(u32 len, void* userdata)
{
    (void)userdata;
    Log(LogLevel::Info, "Headless: rumble requested for %u ms\n", len);
}

void Addon_RumbleStop(void* userdata)
{
    (void)userdata;
    Log(LogLevel::Info, "Headless: rumble stopped\n");
}

float Addon_MotionQuery(MotionQueryType type, void* userdata)
{
    (void)userdata;
    return g_motionValues[type].load(std::memory_order_relaxed);
}

struct DynamicLibrary
{
#ifdef _WIN32
    HMODULE handle = nullptr;
#else
    void* handle = nullptr;
#endif
};

DynamicLibrary* DynamicLibrary_Load(const char* lib)
{
#ifdef _WIN32
    HMODULE handle = LoadLibraryA(lib);
#else
    void* handle = dlopen(lib, RTLD_NOW);
#endif
    if (!handle)
        return nullptr;

    auto* dyn = new DynamicLibrary();
    dyn->handle = handle;
    return dyn;
}

void DynamicLibrary_Unload(DynamicLibrary* lib)
{
    if (!lib)
        return;
#ifdef _WIN32
    if (lib->handle)
        FreeLibrary(lib->handle);
#else
    if (lib->handle)
        dlclose(lib->handle);
#endif
    delete lib;
}

void* DynamicLibrary_LoadFunction(DynamicLibrary* lib, const char* name)
{
    if (!lib || !lib->handle)
        return nullptr;
#ifdef _WIN32
    return reinterpret_cast<void*>(GetProcAddress(lib->handle, name));
#else
    return dlsym(lib->handle, name);
#endif
}

} // namespace melonDS::Platform
