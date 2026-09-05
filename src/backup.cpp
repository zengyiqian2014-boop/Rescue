// backup.cpp - Rescue module 7: ransomware-resilient backup & restore.
//
// The premise of every other module is stopping damage. This one is about
// UNDOING it: after an attack (or a bad disk, or a wipe) the OS can be
// reinstalled from clean media, but the user's own data and settings cannot -
// once encrypted or deleted they are gone unless a copy exists somewhere the
// malware could not reach. So this makes that copy.
//
// WHAT IT BACKS UP (only things a user can change - the OS is deliberately
// excluded, because you restore Windows itself from a clean install, not from a
// backup that might itself carry the infection):
//   * the profile's document folders (Desktop, Documents, Pictures, ...)
//   * Roaming and Local AppData, minus caches/temp (application settings)
//   * the HKCU registry hive (personalization, environment, file associations)
//   * a reference list of installed programs (to know what to reinstall)
//
// WHAT IT DELIBERATELY DOES NOT DO, and why (being straight per the README):
//   * It does not bundle a Windows ISO into the rescue media. Redistributing
//     Windows violates Microsoft's licence; use the official Media Creation
//     Tool for clean media and let this restore the user layer on top.
//   * It is not a "leaves no trace" reboot. That needs write-redirection in a
//     filesystem filter driver (Phase 6, signed) - the same kernel tier that
//     is gated behind driver signing. A user-mode tool cannot do it honestly.
//
// FORMAT: a single .rbk container. Each member is stored compressed (Windows'
// built-in XPRESS_HUFF via ntdll) when that is smaller, otherwise raw - so
// already-compressed files (jpg, mp4, zip) are not wastefully re-packed. The
// format is self-describing (see RbkHeader/RbkEntry) so restore needs no
// external index. REPORT/EXTRACT only; it never deletes source data.
#include <windows.h>
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>
#include <set>
#include "privilege.h"

// --------------------------------------------------- ntdll compression ------
// RtlCompressBuffer / RtlDecompressBufferEx are always present in ntdll but not
// in MinGW's import libs, so bind them at runtime. XPRESS_HUFF gives a good
// ratio at high speed and needs no third-party library.
#define COMP_XPRESS_HUFF 0x0004
#define COMP_ENGINE_MAX  0x0100
#define COMP_FMT (COMP_XPRESS_HUFF | COMP_ENGINE_MAX)

typedef LONG (WINAPI *fnGetWs)(USHORT, PULONG, PULONG);
typedef LONG (WINAPI *fnCompress)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);
typedef LONG (WINAPI *fnDecompress)(USHORT, PUCHAR, ULONG, PUCHAR, ULONG, ULONG, PULONG, PVOID);

static fnGetWs      RtlGetWs      = nullptr;
static fnCompress   RtlCompress   = nullptr;
static fnDecompress RtlDecompress = nullptr;
static ULONG g_wsCompress = 0, g_wsFragment = 0;
static bool  g_canCompress = false;   // both compress+decompress present

// Compression is an optimization, never a requirement: if ntdll doesn't offer
// the full XPRESS_HUFF pair (e.g. an older or non-Windows runtime), we store
// members raw. A store-only backup is still a complete, restorable backup - and
// since we then never mark a member compressed, restore never needs the
// decompressor that was missing.
static void initCompression() {
    HMODULE nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) return;
    RtlGetWs      = (fnGetWs)     (void*)GetProcAddress(nt, "RtlGetCompressionWorkSpaceSize");
    RtlCompress   = (fnCompress)  (void*)GetProcAddress(nt, "RtlCompressBuffer");
    RtlDecompress = (fnDecompress)(void*)GetProcAddress(nt, "RtlDecompressBufferEx");
    if (RtlGetWs && RtlCompress && RtlDecompress && RtlGetWs(COMP_FMT, &g_wsCompress, &g_wsFragment) == 0)
        g_canCompress = true;
}

// Compress 'in' into 'out'. Returns true and sets 'stored=false' if the result
// is genuinely smaller; if compression doesn't help, returns true with
// stored=true and leaves 'out' empty (caller writes the raw buffer instead).
static bool tryCompress(const std::vector<BYTE>& in, std::vector<BYTE>& out, bool& stored) {
    stored = true;
    if (in.empty() || !g_canCompress) return true;
    std::vector<BYTE> ws(g_wsCompress ? g_wsCompress : 1);
    out.resize(in.size());              // never let output exceed input
    ULONG finalSize = 0;
    LONG st = RtlCompress(COMP_FMT, (PUCHAR)in.data(), (ULONG)in.size(),
                          out.data(), (ULONG)out.size(), 4096, &finalSize, ws.data());
    if (st == 0 && finalSize && finalSize < in.size()) {
        out.resize(finalSize);
        stored = false;
    } else {
        out.clear();                    // caller stores raw
    }
    return true;
}

static bool decompress(const std::vector<BYTE>& in, std::vector<BYTE>& out, ULONG originalSize) {
    out.resize(originalSize);
    if (originalSize == 0) return true;
    std::vector<BYTE> ws(g_wsFragment ? g_wsFragment : 1);
    ULONG finalSize = 0;
    LONG st = RtlDecompress(COMP_XPRESS_HUFF, out.data(), originalSize,
                            (PUCHAR)in.data(), (ULONG)in.size(), 0, &finalSize, ws.data());
    if (st != 0 || finalSize != originalSize) return false;
    return true;
}

// ------------------------------------------------------- container format ---
#pragma pack(push, 1)
struct RbkHeader {
    char     magic[8];      // "RESCUEBK"
    uint32_t version;       // 1
    uint64_t createdUtc;    // FILETIME
    uint64_t entryCount;    // members that follow
    uint64_t totalOriginal; // sum of original sizes (for progress on restore)
};
struct RbkEntry {
    uint32_t pathBytes;     // UTF-8 relative path length
    uint32_t storedBytes;   // bytes on disk in the container
    uint64_t originalBytes; // size after decompression
    uint32_t attributes;    // FILE_ATTRIBUTE_*
    uint64_t mtime;         // last-write FILETIME
    uint8_t  compressed;    // 1 = XPRESS_HUFF, 0 = raw
    uint8_t  kind;          // 0 = file, 1 = registry export, 2 = meta text
    uint8_t  reserved[6];
    // followed by: path (pathBytes), then data (storedBytes)
};
#pragma pack(pop)

static const char* kMagic = "RESCUEBK";

// ------------------------------------------------------------- utilities ----
static std::string toUtf8(const std::wstring& w) {
    if (w.empty()) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), nullptr, 0, nullptr, nullptr);
    std::string s(n, 0);
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), (int)w.size(), s.data(), n, nullptr, nullptr);
    return s;
}
static std::wstring fromUtf8(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring w(n, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), w.data(), n);
    return w;
}
static std::wstring lower(std::wstring s) { for (auto& c : s) c = towlower(c); return s; }
static std::wstring envPath(const wchar_t* v) {
    wchar_t b[MAX_PATH * 2]; DWORD n = GetEnvironmentVariableW(v, b, MAX_PATH * 2);
    return (n && n < MAX_PATH * 2) ? std::wstring(b) : std::wstring();
}
static std::wstring humanSize(uint64_t b) {
    const wchar_t* u[] = { L"B", L"KB", L"MB", L"GB", L"TB" };
    double d = (double)b; int i = 0;
    while (d >= 1024 && i < 4) { d /= 1024; ++i; }
    wchar_t s[48]; swprintf(s, 48, L"%.1f %ls", d, u[i]);
    return s;
}

// Directories whose contents are churn/cache, not settings worth restoring.
// Kept as substrings matched case-insensitively against the full path.
static bool isExcluded(const std::wstring& lowFull) {
    static const wchar_t* kSkip[] = {
        L"\\appdata\\local\\temp\\",
        L"\\appdata\\local\\microsoft\\windows\\inetcache\\",
        L"\\appdata\\local\\microsoft\\windows\\explorer\\",       // thumbcache
        L"\\appdata\\local\\microsoft\\windows\\webcache\\",
        L"\\appdata\\local\\packages\\",                            // UWP local caches (large)
        L"\\cache\\", L"\\cache2\\", L"\\gpucache\\", L"\\code cache\\",
        L"\\service worker\\", L"\\crashpad\\", L"\\logs\\",
        L"\\appdata\\locallow\\", L"\\onedrivetemp\\",
    };
    for (auto* s : kSkip) if (lowFull.find(s) != std::wstring::npos) return true;
    return false;
}

// ---------------------------------------------------------------- backup -----
static uint64_t g_files = 0, g_orig = 0, g_stored = 0, g_skipped = 0;

// Append one file to the open container. Large files are stored raw (streamed
// in one read here, capped) to bound memory; smaller files try compression.
static void backupOneFile(FILE* out, const std::wstring& full, const std::wstring& rel) {
    const uint64_t kCompressCap = 64ull * 1024 * 1024;   // compress up to 64 MB
    HANDLE h = CreateFileW(full.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) { ++g_skipped; return; }
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); ++g_skipped; return; }
    BY_HANDLE_FILE_INFORMATION fi{};
    GetFileInformationByHandle(h, &fi);

    std::vector<BYTE> data;
    bool ok = true;
    if ((uint64_t)sz.QuadPart <= kCompressCap) {
        data.resize((size_t)sz.QuadPart);
        DWORD got = 0;
        ok = (sz.QuadPart == 0) ||
             (ReadFile(h, data.data(), (DWORD)data.size(), &got, nullptr) && got == data.size());
    } else {
        // too big to hold twice in memory: store raw, streamed
        data.clear();
    }
    CloseHandle(h);
    if (!ok) { ++g_skipped; return; }

    std::string relU8 = toUtf8(rel);
    RbkEntry e{};
    e.pathBytes    = (uint32_t)relU8.size();
    e.originalBytes = (uint64_t)sz.QuadPart;
    e.attributes   = fi.dwFileAttributes;
    e.mtime        = ((uint64_t)fi.ftLastWriteTime.dwHighDateTime << 32) | fi.ftLastWriteTime.dwLowDateTime;
    e.kind         = 0;

    std::vector<BYTE> comp;
    bool stored = true;
    if (!data.empty()) { tryCompress(data, comp, stored); }

    if ((uint64_t)sz.QuadPart > kCompressCap) {
        // stream the raw bytes straight through
        e.compressed = 0;
        if ((uint64_t)sz.QuadPart > 0xFFFFFFFFull) { ++g_skipped; return; }   // >4GB single file: skip in v1
        e.storedBytes = (uint32_t)sz.QuadPart;
        fwrite(&e, sizeof(e), 1, out);
        fwrite(relU8.data(), 1, relU8.size(), out);
        HANDLE h2 = CreateFileW(full.c_str(), GENERIC_READ,
                                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                                nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        std::vector<BYTE> buf(1u << 20);
        DWORD got = 0;
        while (ReadFile(h2, buf.data(), (DWORD)buf.size(), &got, nullptr) && got)
            fwrite(buf.data(), 1, got, out);
        CloseHandle(h2);
        g_stored += (uint64_t)sz.QuadPart;
    } else if (stored) {
        e.compressed = 0;
        e.storedBytes = (uint32_t)data.size();
        fwrite(&e, sizeof(e), 1, out);
        fwrite(relU8.data(), 1, relU8.size(), out);
        if (!data.empty()) fwrite(data.data(), 1, data.size(), out);
        g_stored += data.size();
    } else {
        e.compressed = 1;
        e.storedBytes = (uint32_t)comp.size();
        fwrite(&e, sizeof(e), 1, out);
        fwrite(relU8.data(), 1, relU8.size(), out);
        fwrite(comp.data(), 1, comp.size(), out);
        g_stored += comp.size();
    }
    ++g_files;
    g_orig += (uint64_t)sz.QuadPart;
}

// Walk a source tree, prefixing container paths with 'label' so restore knows
// where each member belongs (e.g. "Profile\Documents\...", "Roaming\...").
static void backupTree(FILE* out, const std::wstring& root, const std::wstring& label, int depth) {
    if (depth > 40) return;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((root + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;  // no junction loops
        std::wstring full = root + L"\\" + fd.cFileName;
        std::wstring rel  = label + L"\\" + fd.cFileName;
        if (isExcluded(lower(full))) continue;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            backupTree(out, full, rel, depth + 1);
        else
            backupOneFile(out, full, rel);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// Run an external command and capture whether it produced the expected file.
static bool runCmd(const std::wstring& cmd) {
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si); si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) return false;
    WaitForSingleObject(pi.hProcess, 120000);
    DWORD rc = 1; GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return rc == 0;
}

// Add an already-produced file on disk as a container member of a given kind.
static void addMember(FILE* out, const std::wstring& srcPath, const std::wstring& rel, uint8_t kind) {
    HANDLE h = CreateFileW(srcPath.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr,
                           OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return;
    LARGE_INTEGER sz{}; GetFileSizeEx(h, &sz);
    std::vector<BYTE> data((size_t)sz.QuadPart);
    DWORD got = 0;
    if (sz.QuadPart) ReadFile(h, data.data(), (DWORD)data.size(), &got, nullptr);
    CloseHandle(h);

    std::string relU8 = toUtf8(rel);
    RbkEntry e{};
    e.pathBytes = (uint32_t)relU8.size();
    e.originalBytes = (uint64_t)sz.QuadPart;
    e.kind = kind;
    std::vector<BYTE> comp; bool stored = true;
    tryCompress(data, comp, stored);
    if (stored) { e.compressed = 0; e.storedBytes = (uint32_t)data.size(); }
    else        { e.compressed = 1; e.storedBytes = (uint32_t)comp.size(); }
    fwrite(&e, sizeof(e), 1, out);
    fwrite(relU8.data(), 1, relU8.size(), out);
    if (stored) { if (!data.empty()) fwrite(data.data(), 1, data.size(), out); }
    else        fwrite(comp.data(), 1, comp.size(), out);
    ++g_files; g_orig += (uint64_t)sz.QuadPart; g_stored += e.storedBytes;
}

// Capture the boot/partition structures a front/back wipe destroys - the MBR
// and GPT primary at the disk head (LBA 0..33) and the GPT backup at the disk
// tail (last 33 sectors). Stored in the .rbk (off-disk) rather than gambled on
// an "unused middle" sector that might not exist: a copy that lives in your
// backup survives a front+back wipe AND a full wipe, unlike an on-disk copy.
// Read-only; nothing is written to the disk.
static void addRawMember(FILE* out, const std::vector<BYTE>& data, const std::wstring& rel) {
    std::string relU8 = toUtf8(rel);
    RbkEntry e{};
    e.pathBytes = (uint32_t)relU8.size();
    e.originalBytes = data.size();
    e.kind = 3;   // boot/partition raw structure
    std::vector<BYTE> comp; bool stored = true;
    tryCompress(data, comp, stored);
    if (stored) { e.compressed = 0; e.storedBytes = (uint32_t)data.size(); }
    else        { e.compressed = 1; e.storedBytes = (uint32_t)comp.size(); }
    fwrite(&e, sizeof(e), 1, out);
    fwrite(relU8.data(), 1, relU8.size(), out);
    if (stored) { if (!data.empty()) fwrite(data.data(), 1, data.size(), out); }
    else        fwrite(comp.data(), 1, comp.size(), out);
    ++g_files; g_orig += data.size(); g_stored += e.storedBytes;
}

static bool readDiskRegion(HANDLE h, LONGLONG off, DWORD bytes, std::vector<BYTE>& out) {
    LARGE_INTEGER li; li.QuadPart = off;
    if (!SetFilePointerEx(h, li, nullptr, FILE_BEGIN)) return false;
    out.resize(bytes);
    DWORD got = 0;
    return ReadFile(h, out.data(), bytes, &got, nullptr) && got == bytes;
}

static void captureBootStructures(FILE* out) {
    for (int i = 0; i < 16; ++i) {
        wchar_t dev[64]; swprintf(dev, 64, L"\\\\.\\PhysicalDrive%d", i);
        HANDLE h = CreateFileW(dev, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                               nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;

        // head: MBR + GPT primary header + partition entries = first 34 sectors
        std::vector<BYTE> head;
        if (readDiskRegion(h, 0, 34 * 512, head)) {
            wchar_t rel[64]; swprintf(rel, 64, L"Boot\\PhysicalDrive%d.head", i);
            addRawMember(out, head, rel);
            wprintf(L"  boot struct: PhysicalDrive%d MBR + GPT (head)\n", i);
        }
        // tail: GPT backup = last 33 sectors (needs the disk length)
        GET_LENGTH_INFORMATION li{};
        DWORD ret = 0;
        if (DeviceIoControl(h, IOCTL_DISK_GET_LENGTH_INFO, nullptr, 0,
                            &li, sizeof(li), &ret, nullptr) && li.Length.QuadPart > 34 * 512) {
            std::vector<BYTE> tail;
            LONGLONG off = li.Length.QuadPart - 33 * 512;
            if (readDiskRegion(h, off, 33 * 512, tail)) {
                wchar_t rel[64]; swprintf(rel, 64, L"Boot\\PhysicalDrive%d.tail", i);
                addRawMember(out, tail, rel);
                wprintf(L"  boot struct: PhysicalDrive%d GPT backup (tail)\n", i);
            }
        }
        CloseHandle(h);
    }
}

static int doBackup(const std::wstring& outPath) {
    FILE* out = _wfopen(outPath.c_str(), L"wb");
    if (!out) { wprintf(L"[!] cannot create %ls\n", outPath.c_str()); return 1; }

    RbkHeader hdr{};
    memcpy(hdr.magic, kMagic, 8);
    hdr.version = 1;
    FILETIME ft; GetSystemTimeAsFileTime(&ft);
    hdr.createdUtc = ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime;
    fwrite(&hdr, sizeof(hdr), 1, out);       // patched at the end with real counts

    std::wstring up = envPath(L"USERPROFILE");
    wprintf(L"== backing up user data (system files excluded) ==\n");

    // 1. profile document folders
    for (auto* sub : { L"Desktop", L"Documents", L"Pictures", L"Videos", L"Music",
                       L"Downloads", L"Favorites", L"Links", L"Contacts",
                       L"Saved Games", L"Searches", L"OneDrive" }) {
        std::wstring d = up + L"\\" + sub;
        if (GetFileAttributesW(d.c_str()) != INVALID_FILE_ATTRIBUTES) {
            wprintf(L"  profile: %ls\n", sub);
            backupTree(out, d, std::wstring(L"Profile\\") + sub, 0);
        }
    }
    // 2. application settings (Roaming + Local minus caches)
    std::wstring roaming = envPath(L"APPDATA"), local = envPath(L"LOCALAPPDATA");
    if (!roaming.empty()) { wprintf(L"  settings: Roaming AppData\n"); backupTree(out, roaming, L"Roaming", 0); }
    if (!local.empty())   { wprintf(L"  settings: Local AppData (caches excluded)\n"); backupTree(out, local, L"Local", 0); }

    // 3. HKCU registry (personalization, environment, associations) via reg.exe
    std::wstring tmp = envPath(L"TEMP"); if (tmp.empty()) tmp = L"C:\\Windows\\Temp";
    std::wstring reg = tmp + L"\\rescue_hkcu.reg";
    DeleteFileW(reg.c_str());
    if (runCmd(L"reg export HKCU \"" + reg + L"\" /y")) {
        wprintf(L"  settings: HKCU registry hive\n");
        addMember(out, reg, L"Registry\\HKCU.reg", 1);
        DeleteFileW(reg.c_str());
    }
    // 4. installed-program reference list (so the user knows what to reinstall)
    std::wstring plist = tmp + L"\\rescue_programs.reg";
    DeleteFileW(plist.c_str());
    if (runCmd(L"reg export \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\" \"" + plist + L"\" /y")) {
        wprintf(L"  reference: installed-program list\n");
        addMember(out, plist, L"Reference\\installed-programs.reg", 2);
        DeleteFileW(plist.c_str());
    }

    // 5. boot/partition structures (MBR + GPT), so a front/back wipe is recoverable
    captureBootStructures(out);

    // patch header counts
    hdr.entryCount = g_files;
    hdr.totalOriginal = g_orig;
    fseek(out, 0, SEEK_SET);
    fwrite(&hdr, sizeof(hdr), 1, out);
    fclose(out);

    wprintf(L"\n== backup complete ==\n");
    wprintf(L"  container      : %ls\n", outPath.c_str());
    wprintf(L"  members        : %llu\n", (unsigned long long)g_files);
    wprintf(L"  original size  : %ls\n", humanSize(g_orig).c_str());
    wprintf(L"  stored size    : %ls\n", humanSize(g_stored).c_str());
    if (g_orig) wprintf(L"  space saved    : %.0f%%\n", 100.0 * (1.0 - (double)g_stored / (double)g_orig));
    if (g_skipped) wprintf(L"  skipped (locked/too big): %llu\n", (unsigned long long)g_skipped);
    wprintf(L"\nKeep this file on external/offline media - a backup the malware can\n"
            L"reach is not a backup. Restore with:  backup --restore \"%ls\" --to DIR\n", outPath.c_str());
    return 0;
}

// --------------------------------------------------------------- restore -----
static bool readExact(FILE* f, void* p, size_t n) { return fread(p, 1, n, f) == n; }

static bool ensureDirs(const std::wstring& fullPath) {
    // create every parent directory of a file path
    size_t pos = 0;
    for (;;) {
        pos = fullPath.find_first_of(L"\\/", pos + 1);
        if (pos == std::wstring::npos) break;
        std::wstring dir = fullPath.substr(0, pos);
        if (dir.size() >= 2 && dir[1] == L':' && dir.size() == 2) continue;  // "C:"
        CreateDirectoryW(dir.c_str(), nullptr);
    }
    return true;
}

static int doList(const std::wstring& path, bool restore, const std::wstring& dest) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) { wprintf(L"[!] cannot open %ls\n", path.c_str()); return 1; }
    RbkHeader hdr{};
    if (!readExact(f, &hdr, sizeof(hdr)) || memcmp(hdr.magic, kMagic, 8) != 0) {
        wprintf(L"[!] not a Rescue backup container.\n"); fclose(f); return 1;
    }
    wprintf(L"Rescue backup  v%u  members=%llu  original=%ls\n",
            hdr.version, (unsigned long long)hdr.entryCount, humanSize(hdr.totalOriginal).c_str());
    if (restore) {
        if (dest.empty()) { wprintf(L"[!] --restore needs --to DIR\n"); fclose(f); return 2; }
        CreateDirectoryW(dest.c_str(), nullptr);
        wprintf(L"restoring into %ls ...\n", dest.c_str());
    }

    uint64_t done = 0, restored = 0, failed = 0;
    for (uint64_t i = 0; i < hdr.entryCount; ++i) {
        RbkEntry e{};
        if (!readExact(f, &e, sizeof(e))) break;
        std::string relU8(e.pathBytes, 0);
        if (e.pathBytes && !readExact(f, relU8.data(), e.pathBytes)) break;
        std::vector<BYTE> stored(e.storedBytes);
        if (e.storedBytes && !readExact(f, stored.data(), e.storedBytes)) break;
        std::wstring rel = fromUtf8(relU8);
        ++done;

        if (!restore) {
            wprintf(L"  %ls  (%ls%ls)\n", rel.c_str(), humanSize(e.originalBytes).c_str(),
                    e.compressed ? L", compressed" : L"");
            continue;
        }
        // reconstruct
        std::vector<BYTE> data;
        if (e.compressed) {
            if (!g_canCompress || !decompress(stored, data, (ULONG)e.originalBytes)) { ++failed; continue; }
        } else {
            data = std::move(stored);
        }
        // guard against path traversal in a crafted container
        if (rel.find(L"..") != std::wstring::npos) { ++failed; continue; }
        std::wstring outPath = dest + L"\\" + rel;
        ensureDirs(outPath);
        HANDLE h = CreateFileW(outPath.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (h == INVALID_HANDLE_VALUE) { ++failed; continue; }
        DWORD wr = 0;
        if (!data.empty()) WriteFile(h, data.data(), (DWORD)data.size(), &wr, nullptr);
        if (e.mtime) {
            FILETIME ft; ft.dwLowDateTime = (DWORD)e.mtime; ft.dwHighDateTime = (DWORD)(e.mtime >> 32);
            SetFileTime(h, nullptr, nullptr, &ft);
        }
        CloseHandle(h);
        if (e.attributes && e.attributes != FILE_ATTRIBUTE_NORMAL)
            SetFileAttributesW(outPath.c_str(), e.attributes);
        ++restored;
    }
    fclose(f);
    if (restore) {
        wprintf(L"\nrestored %llu member(s), %llu failed.\n",
                (unsigned long long)restored, (unsigned long long)failed);
        wprintf(L"Registry (Registry\\HKCU.reg) and the program list are restored as FILES,\n"
                L"not merged. Review, then double-click HKCU.reg to import if you want it back.\n");
    } else {
        wprintf(L"\n%llu member(s).\n", (unsigned long long)done);
    }
    return failed ? 1 : 0;
}

// ---------------------------------------------------- Time Machine layer ----
// Scheduled, versioned snapshots to a user-chosen backup disk. Each run drops a
// timestamped .rbk under <disk>\RescueBackups\, so the disk accumulates a
// history you can restore any point from - the Windows equivalent of Time
// Machine. A retention count prunes the oldest so the disk doesn't fill up.
static const wchar_t* kSnapDir  = L"RescueBackups";
static const wchar_t* kTaskName = L"Rescue Time Machine";

static std::wstring snapshotFolder(const std::wstring& disk) {
    std::wstring d = disk;
    while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
    return d + L"\\" + kSnapDir;
}

// Delete the oldest snapshots beyond 'keep'. Names sort chronologically
// (rescue-YYYYMMDD-HHMMSS.rbk), so lexical order is time order.
static void pruneSnapshots(const std::wstring& folder, int keep) {
    if (keep <= 0) return;
    std::vector<std::wstring> snaps;
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((folder + L"\\rescue-*.rbk").c_str(), &fd);
    if (h != INVALID_HANDLE_VALUE) {
        do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) snaps.push_back(fd.cFileName); }
        while (FindNextFileW(h, &fd));
        FindClose(h);
    }
    std::sort(snaps.begin(), snaps.end());
    int remove = (int)snaps.size() - keep;
    for (int i = 0; i < remove; ++i) {
        std::wstring victim = folder + L"\\" + snaps[i];
        if (DeleteFileW(victim.c_str()))
            wprintf(L"  pruned old snapshot: %ls\n", snaps[i].c_str());
    }
}

static int doSnapshot(const std::wstring& disk, int keep) {
    DWORD attr = GetFileAttributesW(disk.c_str());
    if (attr == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"[!] backup disk not found: %ls  (is it plugged in?)\n", disk.c_str());
        return 1;
    }
    std::wstring folder = snapshotFolder(disk);
    CreateDirectoryW(folder.c_str(), nullptr);
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t stamp[32];
    swprintf(stamp, 32, L"rescue-%04d%02d%02d-%02d%02d%02d.rbk",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    std::wstring out = folder + L"\\" + stamp;
    wprintf(L"snapshot -> %ls\n", out.c_str());
    int rc = doBackup(out);
    if (rc == 0) pruneSnapshots(folder, keep);
    return rc;
}

static int listSnapshots(const std::wstring& disk) {
    std::wstring folder = snapshotFolder(disk);
    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((folder + L"\\rescue-*.rbk").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) { wprintf(L"no snapshots on %ls\n", disk.c_str()); return 0; }
    std::vector<std::pair<std::wstring, uint64_t>> snaps;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        uint64_t sz = ((uint64_t)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
        snaps.emplace_back(fd.cFileName, sz);
    } while (FindNextFileW(h, &fd));
    FindClose(h);
    std::sort(snaps.begin(), snaps.end());
    wprintf(L"== snapshots on %ls ==\n", folder.c_str());
    for (auto& sp : snaps) wprintf(L"  %ls   %ls\n", sp.first.c_str(), humanSize(sp.second).c_str());
    wprintf(L"%zu snapshot(s). Restore one with:\n  backup --restore \"%ls\\<name>\" --to DIR\n",
            snaps.size(), folder.c_str());
    return 0;
}

// Run schtasks and report success.
static bool schtasks(const std::wstring& args) {
    std::wstring cmd = L"schtasks " + args;
    std::vector<wchar_t> buf(cmd.begin(), cmd.end()); buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW,
                        nullptr, nullptr, &si, &pi)) return false;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD rc = 1; GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return rc == 0;
}

// Translate a preset or a custom every/unit into schtasks /SC and /MO flags.
// Presets encode the guidance the user asked for by data importance.
static bool resolveSchedule(const std::wstring& preset, int every, const std::wstring& unit,
                            std::wstring& scFlags, std::wstring& human) {
    auto set = [&](const wchar_t* sc, int mo, const wchar_t* hm) {
        scFlags = std::wstring(L"/SC ") + sc;
        if (mo > 1) scFlags += L" /MO " + std::to_wstring(mo);
        human = hm;
    };
    if (!preset.empty()) {
        if (preset == L"monthly")   { set(L"MONTHLY", 1, L"once a month (low-importance data)"); return true; }
        if (preset == L"weekly")    { set(L"WEEKLY",  1, L"once a week"); return true; }
        if (preset == L"every5days"){ set(L"DAILY",   5, L"every 5 days (important data)"); return true; }
        if (preset == L"daily")     { set(L"DAILY",   1, L"every day (important data)"); return true; }
        if (preset == L"hourly")    { set(L"HOURLY",  1, L"every hour (critical data)"); return true; }
        wprintf(L"[!] unknown preset: %ls (use monthly|weekly|every5days|daily|hourly)\n", preset.c_str());
        return false;
    }
    if (every > 0 && !unit.empty()) {
        std::wstring u = unit;
        for (auto& c : u) c = towlower(c);
        if (u == L"second" || u == L"seconds") {
            wprintf(L"[!] per-second backups are not possible: a backup takes far longer than\n"
                    L"    a second, and the scheduler's minimum interval is one minute. Use\n"
                    L"    --unit minute (or an importance preset) instead.\n");
            return false;
        }
        if (u == L"minute" || u == L"minutes") { set(L"MINUTE", every, L"custom"); }
        else if (u == L"hour" || u == L"hours"){ set(L"HOURLY", every, L"custom"); }
        else if (u == L"day"  || u == L"days") { set(L"DAILY",  every, L"custom"); }
        else if (u == L"week" || u == L"weeks"){ set(L"WEEKLY", every, L"custom"); }
        else if (u == L"month"|| u == L"months"){ set(L"MONTHLY", every, L"custom"); }
        else { wprintf(L"[!] unknown unit: %ls (minute|hour|day|week|month)\n", unit.c_str()); return false; }
        human = L"every " + std::to_wstring(every) + L" " + unit;
        return true;
    }
    wprintf(L"[!] --schedule needs a preset, or --every N --unit <minute|hour|day|week|month>\n");
    return false;
}

static int scheduleBackup(const std::wstring& disk, const std::wstring& preset,
                          int every, const std::wstring& unit, int keep) {
    if (disk.empty()) { wprintf(L"[!] scheduling needs --disk <backup drive> (e.g. E:)\n"); return 2; }
    std::wstring scFlags, human;
    if (!resolveSchedule(preset, every, unit, scFlags, human)) return 2;

    wchar_t self[MAX_PATH * 2];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH * 2)) return 1;

    // The task runs this same exe as SYSTEM, taking a snapshot to the chosen disk
    // and pruning to 'keep'. Quotes are doubled for schtasks' nested /TR string.
    std::wstring tr = L"\\\"" + std::wstring(self) + L"\\\" --snapshot \\\"" + disk +
                      L"\\\" --keep " + std::to_wstring(keep);
    std::wstring args = L"/Create /F /RU SYSTEM /RL HIGHEST /TN \"" + std::wstring(kTaskName) +
                        L"\" " + scFlags + L" /TR \"" + tr + L"\"";
    if (!schtasks(args)) {
        wprintf(L"[!] scheduling failed (run elevated?).\n");
        return 1;
    }
    wprintf(L"scheduled: Rescue Time Machine, %ls\n", human.c_str());
    wprintf(L"  backup disk : %ls\n", disk.c_str());
    wprintf(L"  keep        : %d most recent snapshots\n", keep);
    wprintf(L"  each run writes a timestamped .rbk to %ls\\%ls\\\n", disk.c_str(), kSnapDir);
    wprintf(L"Manage it in Task Scheduler, or: backup --unschedule / --schedule-status\n");
    return 0;
}

// ------------------------------------------------------------------- main ----
static void usage() {
    wprintf(
        L"Rescue Backup - ransomware-resilient backup of user data & settings\n\n"
        L"  backup --out FILE.rbk        back up profile folders, AppData settings,\n"
        L"                               HKCU registry, and a program list\n"
        L"  backup --list FILE.rbk       show what a container holds\n"
        L"  backup --restore FILE.rbk --to DIR    extract everything under DIR\n\n"
        L"TIME MACHINE (scheduled, versioned snapshots to a backup disk):\n"
        L"  backup --snapshot E: [--keep N]   one timestamped snapshot to E:\\RescueBackups\n"
        L"  backup --list-snapshots E:        list the history on a backup disk\n"
        L"  backup --schedule PRESET --disk E: [--keep N]   automate it\n"
        L"       PRESET = monthly    (low-importance data)\n"
        L"                every5days | daily   (important data)\n"
        L"                hourly     (critical data)\n"
        L"  backup --schedule custom --every N --unit minute|hour|day|week|month --disk E:\n"
        L"  backup --schedule-status | --unschedule\n\n"
        L"The OS itself is deliberately excluded: reinstall Windows from clean media\n"
        L"(the official Media Creation Tool), then restore this user layer on top.\n"
        L"Keep the backup disk external/offline between backups - a backup malware\n"
        L"can reach is not a backup.\n");
}

int wmain(int argc, wchar_t** argv) {
    std::wstring outFile, listFile, restoreFile, dest;
    std::wstring snapDisk, schedPreset, schedDisk, listSnapDisk, unit;
    int keep = 10, every = 0;
    bool wantSchedStatus = false, wantUnschedule = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") { usage(); return 0; }
        else if (a == L"--out" && i + 1 < argc) outFile = argv[++i];
        else if (a == L"--list" && i + 1 < argc) listFile = argv[++i];
        else if (a == L"--restore" && i + 1 < argc) restoreFile = argv[++i];
        else if (a == L"--to" && i + 1 < argc) dest = argv[++i];
        else if (a == L"--snapshot" && i + 1 < argc) snapDisk = argv[++i];
        else if (a == L"--list-snapshots" && i + 1 < argc) listSnapDisk = argv[++i];
        else if (a == L"--schedule" && i + 1 < argc) schedPreset = argv[++i];
        else if (a == L"--disk" && i + 1 < argc) schedDisk = argv[++i];
        else if (a == L"--every" && i + 1 < argc) every = _wtoi(argv[++i]);
        else if (a == L"--unit" && i + 1 < argc) unit = argv[++i];
        else if (a == L"--keep" && i + 1 < argc) keep = _wtoi(argv[++i]);
        else if (a == L"--schedule-status") wantSchedStatus = true;
        else if (a == L"--unschedule") wantUnschedule = true;
        else { wprintf(L"unknown option: %ls\n\n", a.c_str()); usage(); return 2; }
    }

    // schedule management doesn't need privileges/compression
    if (wantUnschedule) {
        bool ok = schtasks(L"/Delete /F /TN \"" + std::wstring(kTaskName) + L"\"");
        wprintf(ok ? L"scheduled backup removed.\n" : L"[!] no scheduled backup, or removal failed.\n");
        return ok ? 0 : 1;
    }
    if (wantSchedStatus) {
        schtasks(L"/Query /TN \"" + std::wstring(kTaskName) + L"\" /V /FO LIST");
        return 0;
    }
    if (!schedPreset.empty())
        return scheduleBackup(schedDisk, schedPreset == L"custom" ? L"" : schedPreset,
                              every, unit, keep);
    if (!listSnapDisk.empty()) return listSnapshots(listSnapDisk);

    if (outFile.empty() && listFile.empty() && restoreFile.empty() && snapDisk.empty()) {
        usage(); return 0;
    }

    initCompression();
    if (!g_canCompress && (!outFile.empty() || !snapDisk.empty()))
        wprintf(L"[i] compression unavailable on this runtime; storing members raw.\n");
    // SYSTEM/Debug so we can read other-profile and ACL-locked user files.
    priv::EnableDebugPrivilege();
    priv::ImpersonateSystem();

    int rc = 0;
    if (!snapDisk.empty())         rc = doSnapshot(snapDisk, keep);
    else if (!outFile.empty())     rc = doBackup(outFile);
    else if (!listFile.empty())    rc = doList(listFile, false, L"");
    else if (!restoreFile.empty()) rc = doList(restoreFile, true, dest);

    priv::Revert();
    return rc;
}
