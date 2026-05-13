#include <iostream>
#include <windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <cstdint>

// ── Constants ────────────────────────────────────────────────────────────────

static constexpr DWORD     ALREADY_PATCHED_OFFSET  = 0x20;
static constexpr BYTE      ALREADY_PATCHED_MARKER  = 0x69;
static constexpr DWORD     PATCH_OFFSET_FROM_MATCH = 4;
static constexpr DWORD     PROCESS_POLL_MS         = 100;
static constexpr DWORD     SCAN_CHUNK_SIZE         = 4 * 1024 * 1024; // 4 MB per chunk

static constexpr DWORD     NEEDED_ACCESS =
    PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE;

static constexpr const char* COSMETICS_SIG   = "80 7E ?? 00 74 05 B0 01 5E 5D C3";
static constexpr const char* COSMETICS_PATCH = "90 90";
// func as of v16.1.0s (6/15/2025)
// 55 8B EC 80 3D 25 0A 46 0D 00 75 14 68 24 F2 34 0D E8 4A 9F 94 FF 83 C4 04 C6 05 25 0A 46 0D 01 56 8B 75 0C 85 F6 74 48 80 7E 65 00 74 05 B0 01 5E 5D C3
//                                                                                                                         ^sig        ^patch

// ── Types ────────────────────────────────────────────────────────────────────

struct SigByte {
    BYTE value;
    bool isWild;
};

// baseAddress is pointer-sized so it survives an x64 build without truncation.
// moduleSize stays DWORD — a single module can't exceed 4 GB.
struct ModuleInfo {
    uintptr_t baseAddress = 0;
    DWORD     moduleSize  = 0;
};

struct ProcessContext {
    DWORD     pid      = 0;
    HANDLE    hProcess = nullptr;
    uintptr_t gaBase   = 0;   // pointer-sized: safe on both x86 and x64
    DWORD     gaSize   = 0;
    HANDLE    hConsole = nullptr;
};

// ── Helpers ───────────────────────────────────────────────────────────────────

static BYTE HexCharToByte(char hi, char lo)
{
    auto nib = [](char c) -> BYTE {
        if (c >= '0' && c <= '9') return static_cast<BYTE>(c - '0');
        if (c >= 'A' && c <= 'F') return static_cast<BYTE>(c - 'A' + 10);
        if (c >= 'a' && c <= 'f') return static_cast<BYTE>(c - 'a' + 10);
        return 0;
    };
    return static_cast<BYTE>((nib(hi) << 4) | nib(lo));
}

static std::vector<SigByte> ParseSignature(const char* sig)
{
    std::vector<SigByte> pattern;
    for (const char* p = sig; *p; ) {
        if (*p == ' ') { ++p; continue; }
        if (*p == '?') {
            pattern.push_back({ 0, true });
            ++p;
            if (*p == '?') ++p;
            continue;
        }
        if (!*(p + 1)) break;
        pattern.push_back({ HexCharToByte(*p, *(p + 1)), false });
        p += 2;
    }
    return pattern;
}

// Scans in SCAN_CHUNK_SIZE chunks with (patLen-1) byte overlap at each boundary
// so patterns that straddle a chunk edge are never missed.
// Memory usage is capped at SCAN_CHUNK_SIZE + patLen instead of the whole module.
static uintptr_t SignatureScan(HANDLE hProcess, uintptr_t base, DWORD totalSize,
                               const std::vector<SigByte>& pattern)
{
    if (pattern.empty() || totalSize == 0) return 0;

    const DWORD patLen  = static_cast<DWORD>(pattern.size());
    const DWORD overlap = patLen - 1; // bytes re-read from previous chunk

    std::vector<BYTE> buf;

    for (DWORD offset = 0; offset < totalSize; offset += SCAN_CHUNK_SIZE) {
        const DWORD remaining = totalSize - offset;
        const DWORD readSize  = min(SCAN_CHUNK_SIZE + overlap, remaining);
        buf.resize(readSize);

        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, (LPCVOID)(base + offset),
                               buf.data(), readSize, &bytesRead)
            || bytesRead < patLen)
            continue;

        for (size_t i = 0; i + patLen <= bytesRead; ++i) {
            bool matched = true;
            for (size_t j = 0; j < patLen; ++j) {
                if (!pattern[j].isWild && buf[i + j] != pattern[j].value) {
                    matched = false;
                    break;
                }
            }
            if (matched) return base + offset + static_cast<DWORD>(i);
        }
    }
    return 0;
}

// Writes bytes into the remote process.
// Checks VirtualProtectEx return values and flushes the instruction cache after
// a successful write so the CPU doesn't execute stale cached instructions.
static bool PatchBytes(HANDLE hProcess, uintptr_t address, const char* bytes)
{
    std::vector<BYTE> patch;
    for (const char* p = bytes; *p; ) {
        if (*p == ' ') { ++p; continue; }
        if (!*(p + 1)) break;
        patch.push_back(HexCharToByte(*p, *(p + 1)));
        p += 2;
    }
    if (patch.empty()) return false;

    DWORD oldProtect = 0, dummy = 0;
    if (!VirtualProtectEx(hProcess, (LPVOID)address,
                          patch.size(), PAGE_EXECUTE_READWRITE, &oldProtect)) {
        std::cerr << "VirtualProtectEx (RWX) failed: " << GetLastError() << '\n';
        return false;
    }

    const bool ok = WriteProcessMemory(hProcess, (LPVOID)address,
                                       patch.data(), patch.size(), nullptr) != 0;

    if (ok)
        FlushInstructionCache(hProcess, (LPVOID)address, patch.size());

    if (!VirtualProtectEx(hProcess, (LPVOID)address, patch.size(), oldProtect, &dummy))
        std::cerr << "VirtualProtectEx (restore) failed: " << GetLastError() << '\n';

    return ok;
}

static ModuleInfo GetModuleInfo(const wchar_t* moduleName, DWORD procID)
{
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procID);
    if (snap == INVALID_HANDLE_VALUE) return {};

    MODULEENTRY32W entry = {};
    entry.dwSize = sizeof(entry);

    if (Module32FirstW(snap, &entry)) {
        do {
            if (wcscmp(entry.szModule, moduleName) == 0) {
                CloseHandle(snap);
                // Cast through uintptr_t: safe on both x86 (32-bit ptr) and x64 (64-bit ptr)
                return { (uintptr_t)entry.modBaseAddr, entry.modBaseSize };
            }
        } while (Module32NextW(snap, &entry));
    }

    CloseHandle(snap);
    return {};
}

static std::string ProcessIdToName(DWORD procID)
{
    std::string ret;
    HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, procID);
    if (handle) {
        DWORD buffSize = 1024;
        CHAR buffer[1024];
        if (QueryFullProcessImageNameA(handle, 0, buffer, &buffSize))
            ret = buffer;
        else
            std::cerr << "QueryFullProcessImageNameA failed: " << GetLastError() << '\n';
        CloseHandle(handle);
    } else {
        std::cerr << "OpenProcess (name query) failed: " << GetLastError() << '\n';
    }
    return ret;
}

static bool AttachProcess(ProcessContext& ctx)
{
    HWND hwnd = FindWindowW(nullptr, L"Among Us");
    if (!hwnd) return false;

    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);

    HANDLE h = OpenProcess(NEEDED_ACCESS, FALSE, pid);
    if (!h) {
        std::cerr << "OpenProcess failed: " << GetLastError() << '\n';
        return false;
    }

    std::string name = ProcessIdToName(pid);
    if (name.empty()) {
        std::cerr << "Could not retrieve process name for PID " << pid << '\n';
        CloseHandle(h);
        return false;
    }

    // Guard against paths with no backslash (e.g. bare filenames)
    const size_t slashPos = name.find_last_of('\\');
    const std::string exe = (slashPos == std::string::npos)
                                ? name
                                : name.substr(slashPos + 1);

    if (exe != "Among Us.exe") {
        std::cerr << "Wrong process: expected \"Among Us.exe\", got \"" << exe << "\"\n";
        CloseHandle(h);
        return false;
    }

    ctx.pid      = pid;
    ctx.hProcess = h;
    std::cout << "Attached to " << exe << " (PID " << pid << ")\n";
    return true;
}

static bool IsProcessAlive(HANDLE hProcess)
{
    return WaitForSingleObject(hProcess, 0) == WAIT_TIMEOUT;
}

static void ApplyPatches(ProcessContext& ctx)
{
    std::cout << "Scanning GameAssembly.dll for injection point...\n";

    const std::vector<SigByte> pattern = ParseSignature(COSMETICS_SIG);
    const uintptr_t matchAddr = SignatureScan(ctx.hProcess, ctx.gaBase, ctx.gaSize, pattern);

    if (matchAddr == 0) {
        SetConsoleTextAttribute(ctx.hConsole, 0xC);
        std::cout << "Scan FAIL — unsupported game version or signature not found.\n";
        SetConsoleTextAttribute(ctx.hConsole, 0x7);
        system("pause");
        return;
    }

    SetConsoleTextAttribute(ctx.hConsole, 0xA);
    std::cout << "Scan OK at 0x" << std::hex << matchAddr << std::dec << '\n';

    const uintptr_t patchAddr = matchAddr + PATCH_OFFSET_FROM_MATCH;
    if (!PatchBytes(ctx.hProcess, patchAddr, COSMETICS_PATCH)) {
        SetConsoleTextAttribute(ctx.hConsole, 0xC);
        std::cout << "Patch write failed — aborting.\n";
        SetConsoleTextAttribute(ctx.hConsole, 0x7);
        return; // do NOT write the marker; next run should retry patching
    }

    // Only mark as patched after all writes succeed
    PatchBytes(ctx.hProcess, ctx.gaBase + ALREADY_PATCHED_OFFSET, "69");

    SetConsoleTextAttribute(ctx.hConsole, 0xA);
    std::cout << "All patches applied — ready to go!\n";
    SetConsoleTextAttribute(ctx.hConsole, 0x7);
}

static void RunOnce(ProcessContext& ctx)
{
    if (!AttachProcess(ctx)) {
        std::cout << "Waiting for Among Us to start...\n";
        while (!AttachProcess(ctx))
            Sleep(PROCESS_POLL_MS);
    }

    std::cout << "Waiting for GameAssembly.dll to load...\n";
    while (IsProcessAlive(ctx.hProcess)) {
        ModuleInfo ga = GetModuleInfo(L"GameAssembly.dll", ctx.pid);
        if (ga.baseAddress && ga.moduleSize) {
            ctx.gaBase = ga.baseAddress;
            ctx.gaSize = ga.moduleSize;
            std::cout << "GameAssembly.dll at 0x" << std::hex << ctx.gaBase << std::dec
                      << "  size 0x" << std::hex << ctx.gaSize << std::dec << '\n';
            break;
        }
        Sleep(PROCESS_POLL_MS);
    }
    if (!IsProcessAlive(ctx.hProcess)) return;

    BYTE marker = 0;
    ReadProcessMemory(ctx.hProcess,
                      (LPCVOID)(ctx.gaBase + ALREADY_PATCHED_OFFSET),
                      &marker, 1, nullptr);
    if (marker == ALREADY_PATCHED_MARKER) {
        SetConsoleTextAttribute(ctx.hConsole, 0xA);
        std::cout << "This process was already patched — ready to go!\n";
        SetConsoleTextAttribute(ctx.hConsole, 0x7);
    } else {
        ApplyPatches(ctx);
    }

    WaitForSingleObject(ctx.hProcess, INFINITE);
    std::cout << "Game closed — waiting for next launch...\n";
}

int main()
{
    SetConsoleTitleA("HackerHansen's Among Us Cosmetics Unlocker for v16.1.0s (updated 6/15/2025)");
    std::cout << "Starting!\n";
    std::cout << "If you can afford to buy cosmetics, consider doing so to support the devs.\n";

    ProcessContext ctx;
    ctx.hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

    while (true) {
        RunOnce(ctx);
        if (ctx.hProcess) { CloseHandle(ctx.hProcess); ctx.hProcess = nullptr; }
        const HANDLE hCon = ctx.hConsole;
        ctx = {};
        ctx.hConsole = hCon;
    }
}
