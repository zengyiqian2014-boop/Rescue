// scanner.cpp - Rescue module 4: on-demand file scanner.
//
// The honest problem with "write an antivirus scanner": a real signature
// database is an operational product (millions of samples, daily updates), not
// something a source tree can ship. So this scanner is built on the three
// things that DO work without a virus database:
//
//   1. Authenticode trust (signature.h) - a file vouched for by a trusted
//      signer is the overwhelming majority of what is on a clean disk. Getting
//      it out of the way first is what makes scanning the rest affordable.
//   2. Mark-of-the-Web - Windows records, in an alternate data stream, that a
//      file came off the internet. Downloaded + unsigned + executable is the
//      single highest-yield triage signal on a real infection, so MOTW files
//      get top priority and a deeper look.
//   3. Structural heuristics on the PE itself - packer-grade entropy, a
//      writable+executable section, a near-empty import table, a name that
//      masquerades as a system binary from the wrong directory, a double
//      extension. None of these is proof; scored together they rank what a
//      human should look at first.
//
// On top of that it takes an optional SHA-256 blocklist (--db) for known-bad
// hashes, and will hand candidates to a locally installed ClamAV
// (clamdscan/clamscan) if you pass --clam. Rescue does not vendor libclamav -
// it is an MSVC/autotools C library that does not cross-compile with MinGW, and
// pretending otherwise would be worse than delegating to a real install.
//
// REPORT-ONLY BY DEFAULT. --quarantine moves detections aside (reversibly:
// every quarantined file gets a manifest entry and can be restored).
#include <windows.h>
#include <bcrypt.h>
#include <shlwapi.h>
#include <cstdio>
#include <cmath>
#include <string>
#include <vector>
#include <algorithm>
#include "privilege.h"
#include "signature.h"

#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
#endif

// ---------------------------------------------------------------- options ---
static bool   g_full = false;
static bool   g_quarantine = false;
static bool   g_clam = false;
static int    g_minScore = 4;
static std::vector<std::wstring> g_paths;
static std::wstring g_db;

static long long g_scanned = 0, g_skippedTrusted = 0, g_detections = 0, g_quarantined = 0;

// ------------------------------------------------------------- utilities ---
static std::wstring lower(std::wstring s) {
    std::transform(s.begin(), s.end(), s.begin(), ::towlower);
    return s;
}

static std::wstring fileName(const std::wstring& p) {
    size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? p : p.substr(s + 1);
}

static std::wstring extOf(const std::wstring& p) {
    std::wstring n = fileName(p);
    size_t d = n.find_last_of(L'.');
    return d == std::wstring::npos ? L"" : lower(n.substr(d + 1));
}

static std::wstring envPath(const wchar_t* var) {
    wchar_t buf[MAX_PATH * 2];
    DWORD n = GetEnvironmentVariableW(var, buf, MAX_PATH * 2);
    return (n && n < MAX_PATH * 2) ? std::wstring(buf) : std::wstring();
}

// Extensions worth opening. Everything else is skipped unless it carries a
// Mark-of-the-Web (a downloaded file with an odd extension is still worth a
// look, and it is cheap because MOTW is checked before the file is read).
static bool interestingExt(const std::wstring& e) {
    static const wchar_t* kExts[] = {
        L"exe", L"dll", L"sys", L"scr", L"com", L"ocx", L"cpl", L"drv", L"efi",
        L"ps1", L"psm1", L"vbs", L"vbe", L"js", L"jse", L"wsf", L"wsh", L"hta",
        L"bat", L"cmd", L"lnk", L"msi", L"msp", L"pif", L"jar", L"reg"
    };
    for (const wchar_t* x : kExts) if (e == x) return true;
    return false;
}

static bool isScriptExt(const std::wstring& e) {
    static const wchar_t* kExts[] = { L"ps1", L"psm1", L"vbs", L"vbe", L"js",
                                      L"jse", L"wsf", L"wsh", L"hta", L"bat", L"cmd" };
    for (const wchar_t* x : kExts) if (e == x) return true;
    return false;
}

// ------------------------------------------------------------- SHA-256 ----
// CNG rather than the deprecated CryptoAPI; MinGW links -lbcrypt. The explicit
// create/hash/finish sequence is used rather than the one-shot BCryptHash
// because llvm-mingw's headers (ARM64 target) do not declare the latter.
static bool sha256(const std::vector<BYTE>& data, std::wstring& out) {
    BCRYPT_ALG_HANDLE alg = nullptr;
    if (BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0) != STATUS_SUCCESS)
        return false;
    BYTE digest[32]{};
    BCRYPT_HASH_HANDLE h = nullptr;
    NTSTATUS st = BCryptCreateHash(alg, &h, nullptr, 0, nullptr, 0, 0);
    if (st == STATUS_SUCCESS) {
        st = BCryptHashData(h, const_cast<BYTE*>(data.data()), (ULONG)data.size(), 0);
        if (st == STATUS_SUCCESS) st = BCryptFinishHash(h, digest, sizeof(digest), 0);
        BCryptDestroyHash(h);
    }
    BCryptCloseAlgorithmProvider(alg, 0);
    if (st != STATUS_SUCCESS) return false;
    const wchar_t* hx = L"0123456789abcdef";
    out.clear();
    for (BYTE b : digest) { out += hx[b >> 4]; out += hx[b & 0xF]; }
    return true;
}

// ----------------------------------------------------------- hash blocklist -
// Plain text, one entry per line:  <sha256 hex>  [optional name]
// '#' starts a comment. Kept deliberately simple so an operator can paste in
// IOC hashes from an incident report or a threat feed.
static std::vector<std::pair<std::wstring, std::wstring>> g_blocklist;

static void loadBlocklist(const std::wstring& path) {
    FILE* f = _wfopen(path.c_str(), L"rb");
    if (!f) { wprintf(L"[!] cannot open hash DB: %ls\n", path.c_str()); return; }
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        std::string s(line);
        size_t h = s.find('#'); if (h != std::string::npos) s = s.substr(0, h);
        size_t b = s.find_first_not_of(" \t\r\n");
        if (b == std::string::npos) continue;
        s = s.substr(b);
        size_t sp = s.find_first_of(" \t\r\n");
        std::string hex = s.substr(0, sp);
        if (hex.size() != 64) continue;
        std::string name;
        if (sp != std::string::npos) {
            size_t nb = s.find_first_not_of(" \t", sp);
            if (nb != std::string::npos) {
                name = s.substr(nb);
                while (!name.empty() && (name.back() == '\n' || name.back() == '\r')) name.pop_back();
            }
        }
        std::wstring whex(hex.begin(), hex.end());
        std::wstring wname(name.begin(), name.end());
        g_blocklist.emplace_back(lower(whex), wname);
    }
    fclose(f);
    wprintf(L"[i] hash blocklist: %zu entries from %ls\n", g_blocklist.size(), path.c_str());
}

static const std::wstring* blocklistHit(const std::wstring& hash) {
    for (auto& e : g_blocklist) if (e.first == hash) return &e.second;
    return nullptr;
}

// ------------------------------------------------------- Mark-of-the-Web ---
// Windows stores download provenance in the :Zone.Identifier alternate data
// stream. ZoneId 3 = internet, 4 = restricted. HostUrl (when present) names
// where it came from, which is the most useful line in a triage report.
struct Motw { bool present = false; int zone = 0; std::wstring host; };

static Motw readMotw(const std::wstring& path) {
    Motw m;
    HANDLE h = CreateFileW((path + L":Zone.Identifier").c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return m;
    char buf[4096]{};
    DWORD got = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, nullptr) && got) {
        m.present = true;
        std::string s(buf, got);
        size_t z = s.find("ZoneId=");
        if (z != std::string::npos) m.zone = atoi(s.c_str() + z + 7);
        size_t u = s.find("HostUrl=");
        if (u == std::string::npos) u = s.find("ReferrerUrl=");
        if (u != std::string::npos) {
            size_t vs = s.find('=', u) + 1;
            size_t ve = s.find_first_of("\r\n", vs);
            std::string url = s.substr(vs, ve == std::string::npos ? std::string::npos : ve - vs);
            if (url.size() > 160) url = url.substr(0, 160) + "...";
            m.host.assign(url.begin(), url.end());
        }
    }
    CloseHandle(h);
    return m;
}

// ---------------------------------------------------------------- entropy --
// Shannon entropy in bits/byte. ~7.9+ over a whole file means compressed or
// encrypted; in a PE *code* section that is the classic packer tell, because
// real x86/ARM code sits around 6.
static double entropy(const BYTE* p, size_t n) {
    if (!n) return 0.0;
    size_t freq[256]{};
    for (size_t i = 0; i < n; ++i) ++freq[p[i]];
    double e = 0.0;
    for (size_t i = 0; i < 256; ++i) {
        if (!freq[i]) continue;
        double pr = (double)freq[i] / (double)n;
        e -= pr * log2(pr);
    }
    return e;
}

// ------------------------------------------------------------- PE parsing --
struct PeInfo {
    bool  isPe = false;
    bool  isDll = false;
    bool  wxSection = false;      // a section both writable and executable
    bool  oddSectionName = false; // UPX0, .aspack, non-printable, ...
    bool  noImports = false;      // import directory empty/absent
    int   importDlls = 0;
    bool  hasTls = false;         // TLS callbacks: common anti-debug / early exec
    double codeEntropy = 0.0;
    double maxSectionEntropy = 0.0;
    double overlayRatio = 0.0;    // appended data beyond the last section
};

static bool parsePe(const std::vector<BYTE>& d, PeInfo& pe) {
    if (d.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    auto* dos = (const IMAGE_DOS_HEADER*)d.data();
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0 || (size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS32) > d.size())
        return false;
    auto* nt = (const IMAGE_NT_HEADERS32*)(d.data() + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    pe.isPe = true;
    pe.isDll = (nt->FileHeader.Characteristics & IMAGE_FILE_DLL) != 0;

    bool pe32plus = nt->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    const IMAGE_DATA_DIRECTORY* dirs = nullptr;
    DWORD numDirs = 0;
    if (pe32plus) {
        if ((size_t)dos->e_lfanew + sizeof(IMAGE_NT_HEADERS64) > d.size()) return true;
        auto* nt64 = (const IMAGE_NT_HEADERS64*)nt;
        dirs = nt64->OptionalHeader.DataDirectory;
        numDirs = nt64->OptionalHeader.NumberOfRvaAndSizes;
    } else {
        dirs = nt->OptionalHeader.DataDirectory;
        numDirs = nt->OptionalHeader.NumberOfRvaAndSizes;
    }
    if (numDirs > IMAGE_NUMBEROF_DIRECTORY_ENTRIES) numDirs = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

    if (numDirs > IMAGE_DIRECTORY_ENTRY_TLS && dirs[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress)
        pe.hasTls = true;
    bool haveImportDir = numDirs > IMAGE_DIRECTORY_ENTRY_IMPORT &&
                         dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress != 0;

    // Sections: entropy, permissions, names, and the file offset map we need to
    // find the import table on disk.
    auto* sec = IMAGE_FIRST_SECTION(nt);
    size_t secOff = (size_t)((const BYTE*)sec - d.data());
    WORD n = nt->FileHeader.NumberOfSections;
    if (n > 96) n = 96;
    if (secOff + (size_t)n * sizeof(IMAGE_SECTION_HEADER) > d.size()) return true;

    static const wchar_t* kPackerNames[] = { L"upx0", L"upx1", L"upx2", L".aspack",
                                             L".adata", L".themida", L".vmp0", L".vmp1",
                                             L".petite", L".mpress1", L".enigma1" };
    DWORD lastEnd = 0;
    for (WORD i = 0; i < n; ++i) {
        const IMAGE_SECTION_HEADER& s = sec[i];
        DWORD off = s.PointerToRawData, sz = s.SizeOfRawData;
        if (off < d.size() && sz && (size_t)off + sz <= d.size()) {
            double e = entropy(d.data() + off, sz);
            pe.maxSectionEntropy = (std::max)(pe.maxSectionEntropy, e);
            if (s.Characteristics & IMAGE_SCN_CNT_CODE ||
                s.Characteristics & IMAGE_SCN_MEM_EXECUTE)
                pe.codeEntropy = (std::max)(pe.codeEntropy, e);
        }
        if ((s.Characteristics & IMAGE_SCN_MEM_WRITE) &&
            (s.Characteristics & IMAGE_SCN_MEM_EXECUTE))
            pe.wxSection = true;

        char nameA[9]{};
        memcpy(nameA, s.Name, 8);
        std::wstring nameW;
        for (int k = 0; k < 8 && nameA[k]; ++k) {
            unsigned char c = (unsigned char)nameA[k];
            if (c < 0x20 || c > 0x7E) { pe.oddSectionName = true; break; }
            nameW += (wchar_t)c;
        }
        std::wstring nl = lower(nameW);
        for (const wchar_t* pn : kPackerNames) if (nl == pn) pe.oddSectionName = true;

        if ((size_t)off + sz > lastEnd) lastEnd = off + sz;
    }
    if (d.size() > lastEnd && lastEnd)
        pe.overlayRatio = (double)(d.size() - lastEnd) / (double)d.size();

    // Count imported DLLs by walking the import descriptors on disk. A packed
    // stub typically imports LoadLibrary/GetProcAddress from one DLL and
    // resolves the rest at runtime, so a very small count is a (weak) tell.
    auto rvaToOff = [&](DWORD rva) -> DWORD {
        for (WORD i = 0; i < n; ++i) {
            const IMAGE_SECTION_HEADER& s = sec[i];
            if (rva >= s.VirtualAddress && rva < s.VirtualAddress + (std::max)(s.Misc.VirtualSize, s.SizeOfRawData))
                return s.PointerToRawData + (rva - s.VirtualAddress);
        }
        return 0;
    };
    if (haveImportDir) {
        DWORD off = rvaToOff(dirs[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        while (off && (size_t)off + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= d.size()) {
            auto* imp = (const IMAGE_IMPORT_DESCRIPTOR*)(d.data() + off);
            if (!imp->Name && !imp->FirstThunk) break;
            if (++pe.importDlls > 64) break;
            off += sizeof(IMAGE_IMPORT_DESCRIPTOR);
        }
    }
    pe.noImports = pe.importDlls == 0;
    return true;
}

// ---------------------------------------------------------- script triage --
// Script droppers are mostly one shape: a base64 / obfuscated blob handed to an
// interpreter with the window hidden and the execution policy bypassed. These
// are markers, not proof - admin scripts use some of them legitimately - so
// each contributes a point rather than a verdict.
struct Marker { const char* needle; const wchar_t* why; int score; };

static const Marker kScriptMarkers[] = {
    { "frombase64string",      L"base64-decodes a payload",              2 },
    { "-encodedcommand",       L"PowerShell -EncodedCommand",            3 },
    { " -enc ",                L"PowerShell -enc (encoded command)",     3 },
    { "invoke-expression",     L"Invoke-Expression on built-up text",    2 },
    { "iex(",                  L"IEX on built-up text",                  2 },
    { "downloadstring",        L"downloads and runs code from a URL",    3 },
    { "downloadfile",          L"downloads a file",                      2 },
    { "-windowstyle hidden",   L"runs with the window hidden",           2 },
    { "-w hidden",             L"runs with the window hidden",           2 },
    { "-executionpolicy bypass", L"bypasses the execution policy",       2 },
    { "-ep bypass",            L"bypasses the execution policy",         2 },
    { "wscript.shell",         L"shells out via WScript.Shell",          1 },
    { "powershell",            L"launches PowerShell",                   1 },
    { "certutil -decode",      L"certutil used as a decoder",            3 },
    { "bitsadmin /transfer",   L"bitsadmin used as a downloader",        3 },
    { "vssadmin delete shadows", L"deletes Volume Shadow Copies",        6 },
    { "wbadmin delete catalog",  L"deletes the backup catalog",          6 },
    { "bcdedit /set recoveryenabled no", L"disables Windows recovery",   6 },
    { "cipher /w",             L"wipes free space",                      3 },
    { "add-mppreference -exclusionpath", L"adds a Defender exclusion",   5 },
    { "set-mppreference -disablerealtimemonitoring", L"disables Defender", 6 },
};

// ------------------------------------------------------------- detection ---
struct Finding {
    std::wstring path;
    std::wstring hash;
    int score = 0;
    sig::Trust trust = sig::Trust::Unsigned;
    std::wstring signer;
    std::vector<std::wstring> reasons;
    bool known = false;   // matched the hash blocklist: a fact, not a heuristic
};

static bool inAnyOf(const std::wstring& lowPath, std::initializer_list<const wchar_t*> parts) {
    for (const wchar_t* p : parts) if (lowPath.find(p) != std::wstring::npos) return true;
    return false;
}

// System binaries malware likes to impersonate from a directory they never
// live in. A "svchost.exe" outside System32 is not a coincidence.
static bool masqueradingName(const std::wstring& lowName, const std::wstring& lowPath) {
    static const wchar_t* kNames[] = {
        L"svchost.exe", L"lsass.exe", L"csrss.exe", L"services.exe", L"winlogon.exe",
        L"explorer.exe", L"smss.exe", L"wininit.exe", L"spoolsv.exe", L"taskhostw.exe",
        L"dllhost.exe", L"conhost.exe", L"rundll32.exe", L"ctfmon.exe"
    };
    bool named = false;
    for (const wchar_t* n : kNames) if (lowName == n) { named = true; break; }
    if (!named) return false;
    return !inAnyOf(lowPath, { L"\\windows\\system32\\", L"\\windows\\syswow64\\",
                               L"\\windows\\winsxs\\", L"\\windows\\explorer.exe" });
}

// A file called "invoice.pdf.exe": the first extension is cosmetic, the second
// is what runs. Only counts when the trailing extension is executable.
static bool doubleExtension(const std::wstring& lowName) {
    static const wchar_t* kLures[] = { L".pdf", L".doc", L".docx", L".xls", L".xlsx",
                                       L".jpg", L".jpeg", L".png", L".txt", L".zip",
                                       L".rar", L".mp4", L".ppt", L".pptx", L".csv" };
    std::wstring e = extOf(lowName);
    if (e != L"exe" && e != L"scr" && e != L"com" && e != L"pif" && e != L"bat" &&
        e != L"cmd" && e != L"js" && e != L"vbs" && e != L"hta")
        return false;
    size_t d = lowName.find_last_of(L'.');
    if (d == std::wstring::npos) return false;
    std::wstring stem = lowName.substr(0, d);
    for (const wchar_t* l : kLures)
        if (stem.size() > wcslen(l) && stem.compare(stem.size() - wcslen(l), wcslen(l), l) == 0)
            return true;
    return false;
}

static bool readFile(const std::wstring& path, std::vector<BYTE>& out, size_t cap, ULONGLONG* fullSize) {
    HANDLE h = CreateFileW(path.c_str(), GENERIC_READ,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    LARGE_INTEGER sz{};
    if (!GetFileSizeEx(h, &sz)) { CloseHandle(h); return false; }
    if (fullSize) *fullSize = (ULONGLONG)sz.QuadPart;
    size_t want = (size_t)(std::min)((ULONGLONG)cap, (ULONGLONG)sz.QuadPart);
    out.resize(want);
    DWORD got = 0;
    bool ok = want == 0 || (ReadFile(h, out.data(), (DWORD)want, &got, nullptr) && got == want);
    CloseHandle(h);
    if (!ok) out.clear();
    return ok;
}

// The scan of a single file. Returns true if it scored at or above the report
// threshold. Scoring is additive and every point carries a printed reason, so a
// reviewer can always see *why* a file was ranked where it was.
static bool scanFile(const std::wstring& path, Finding& f) {
    const size_t kCap = 8u * 1024 * 1024;   // hash and inspect the first 8 MB
    std::wstring lowPath = lower(path);
    std::wstring lowName = lower(fileName(path));
    std::wstring ext = extOf(lowName);

    Motw motw = readMotw(path);
    if (!interestingExt(ext) && !motw.present) return false;

    ULONGLONG fullSize = 0;
    std::vector<BYTE> data;
    if (!readFile(path, data, kCap, &fullSize)) return false;
    if (data.empty()) return false;
    ++g_scanned;

    f.path = path;
    sha256(data, f.hash);

    // --- known-bad hash: a verified match, not a heuristic ---
    if (const std::wstring* name = blocklistHit(f.hash)) {
        f.known = true;
        f.score = 100;
        f.reasons.push_back(L"SHA-256 matches hash blocklist" +
                            (name->empty() ? L"" : L" (" + *name + L")"));
    }

    // --- trust first: it is the cheapest way to clear most of a disk ---
    f.trust = sig::Verify(path, &f.signer);
    if (sig::IsTrusted(f.trust) && !f.known) { ++g_skippedTrusted; return false; }

    // --- provenance ---
    if (motw.present && (motw.zone == 3 || motw.zone == 4)) {
        f.score += 2;
        f.reasons.push_back(L"downloaded from the internet (Mark-of-the-Web)" +
                            (motw.host.empty() ? L"" : L": " + motw.host));
    }
    if (inAnyOf(lowPath, { L"\\appdata\\local\\temp\\", L"\\windows\\temp\\",
                           L"\\appdata\\roaming\\", L"\\programdata\\",
                           L"\\users\\public\\", L"\\$recycle.bin\\" })) {
        f.score += 2;
        f.reasons.push_back(L"executable living in a temp/roaming/public directory");
    }
    DWORD attr = GetFileAttributesW(path.c_str());
    if (attr != INVALID_FILE_ATTRIBUTES &&
        (attr & FILE_ATTRIBUTE_HIDDEN) && (attr & FILE_ATTRIBUTE_SYSTEM) &&
        !inAnyOf(lowPath, { L"\\windows\\" })) {
        f.score += 2;
        f.reasons.push_back(L"hidden + system attributes outside \\Windows");
    }
    if (doubleExtension(lowName)) {
        f.score += 4;
        f.reasons.push_back(L"double extension - the visible one is a lure");
    }
    if (masqueradingName(lowName, lowPath)) {
        f.score += 4;
        f.reasons.push_back(L"named like a Windows system binary but not in System32");
    }

    // --- structure ---
    PeInfo pe;
    if (parsePe(data, pe)) {
        if (f.trust == sig::Trust::Untrusted) {
            f.score += 2;
            f.reasons.push_back(L"signature present but does not verify");
        } else {
            f.score += 1;
            f.reasons.push_back(L"unsigned executable");
        }
        if (pe.codeEntropy > 7.0) {
            f.score += 2;
            wchar_t b[96]; swprintf(b, 96, L"packed/encrypted code section (entropy %.2f)", pe.codeEntropy);
            f.reasons.push_back(b);
        } else if (pe.maxSectionEntropy > 7.5) {
            f.score += 1;
            wchar_t b[96]; swprintf(b, 96, L"high-entropy section (%.2f) - packed or embedded payload", pe.maxSectionEntropy);
            f.reasons.push_back(b);
        }
        if (pe.wxSection) {
            f.score += 2;
            f.reasons.push_back(L"section is both writable and executable (self-modifying/unpacking)");
        }
        if (pe.oddSectionName) {
            f.score += 2;
            f.reasons.push_back(L"packer-style or non-printable section name");
        }
        if (pe.noImports) {
            f.score += 2;
            f.reasons.push_back(L"no import table - resolves APIs at runtime");
        } else if (pe.importDlls <= 2) {
            f.score += 1;
            wchar_t b[80]; swprintf(b, 80, L"imports from only %d DLL(s)", pe.importDlls);
            f.reasons.push_back(b);
        }
        if (pe.hasTls) {
            f.score += 1;
            f.reasons.push_back(L"TLS callbacks (code runs before main - anti-debug pattern)");
        }
        if (pe.overlayRatio > 0.5 && fullSize > 64 * 1024) {
            f.score += 1;
            f.reasons.push_back(L"most of the file is appended overlay data");
        }
    } else if (isScriptExt(ext)) {
        // Case-fold the text once, then look for the dropper markers. UTF-16
        // scripts are handled by also folding a byte-stripped copy.
        std::string text((const char*)data.data(), (std::min)(data.size(), (size_t)512 * 1024));
        std::string folded;
        folded.reserve(text.size());
        for (char c : text) if (c) folded += (char)tolower((unsigned char)c);
        int markerScore = 0;
        for (const Marker& m : kScriptMarkers) {
            if (folded.find(m.needle) == std::string::npos) continue;
            markerScore += m.score;
            f.reasons.push_back(std::wstring(L"script marker: ") + m.why);
        }
        // Cap the marker contribution: a long admin script can trip several
        // benign markers, and no pile of weak signals should outrank a fact.
        f.score += (std::min)(markerScore, 10);
        double e = entropy(data.data(), data.size());
        if (e > 5.9 && data.size() > 2048) {
            f.score += 2;
            wchar_t b[96]; swprintf(b, 96, L"obfuscated script text (entropy %.2f)", e);
            f.reasons.push_back(b);
        }
    } else if (ext == L"lnk") {
        std::string text((const char*)data.data(), data.size());
        std::string folded;
        for (char c : text) if (c) folded += (char)tolower((unsigned char)c);
        if (folded.find("powershell") != std::string::npos ||
            folded.find("mshta") != std::string::npos ||
            folded.find("cmd.exe /c") != std::string::npos) {
            f.score += 3;
            f.reasons.push_back(L"shortcut launches an interpreter (classic .lnk dropper)");
        }
        if (folded.find("-enc") != std::string::npos ||
            folded.find("frombase64string") != std::string::npos) {
            f.score += 3;
            f.reasons.push_back(L"shortcut carries an encoded command");
        }
    } else {
        return false;   // not a PE, not a script, nothing structural to say
    }

    return f.score >= g_minScore;
}

// ------------------------------------------------------------ quarantine ---
// Reversible by construction: the file is MOVED (never deleted) into
// %ProgramData%\Rescue\Quarantine and an append-only manifest records where it
// came from and why, so --restore can put it back.
static std::wstring quarantineDir() {
    std::wstring pd = envPath(L"ProgramData");
    if (pd.empty()) pd = L"C:\\ProgramData";
    return pd + L"\\Rescue\\Quarantine";
}

static bool ensureDir(const std::wstring& dir) {
    if (CreateDirectoryW(dir.c_str(), nullptr)) return true;
    return GetLastError() == ERROR_ALREADY_EXISTS;
}

static bool ensureQuarantineDir() {
    std::wstring pd = envPath(L"ProgramData");
    if (pd.empty()) pd = L"C:\\ProgramData";
    ensureDir(pd + L"\\Rescue");
    return ensureDir(quarantineDir());
}

static void appendManifest(const std::wstring& id, const Finding& f) {
    std::wstring mf = quarantineDir() + L"\\manifest.txt";
    FILE* fp = _wfopen(mf.c_str(), L"a, ccs=UTF-8");
    if (!fp) return;
    SYSTEMTIME st; GetLocalTime(&st);
    fwprintf(fp, L"%04d-%02d-%02d %02d:%02d:%02d\t%ls\t%ls\t%ls\tscore=%d\n",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
             id.c_str(), f.path.c_str(), f.hash.c_str(), f.score);
    for (auto& r : f.reasons) fwprintf(fp, L"\t\t%ls\n", r.c_str());
    fclose(fp);
}

static bool quarantineFile(const Finding& f) {
    if (!ensureQuarantineDir()) { wprintf(L"      [!] cannot create quarantine directory\n"); return false; }
    SYSTEMTIME st; GetLocalTime(&st);
    wchar_t stamp[64];
    swprintf(stamp, 64, L"%04d%02d%02d-%02d%02d%02d", st.wYear, st.wMonth, st.wDay,
             st.wHour, st.wMinute, st.wSecond);
    std::wstring id = std::wstring(stamp) + L"_" + fileName(f.path) + L".quar";
    std::wstring dest = quarantineDir() + L"\\" + id;
    // Clear attributes first: hidden/system/read-only would block the move.
    SetFileAttributesW(f.path.c_str(), FILE_ATTRIBUTE_NORMAL);
    if (!MoveFileExW(f.path.c_str(), dest.c_str(), MOVEFILE_REPLACE_EXISTING)) {
        wprintf(L"      [!] quarantine failed (error %lu) - file may be running\n", GetLastError());
        return false;
    }
    appendManifest(id, f);
    wprintf(L"      -> quarantined as %ls\n", id.c_str());
    return true;
}

static void listQuarantine() {
    std::wstring mf = quarantineDir() + L"\\manifest.txt";
    FILE* fp = _wfopen(mf.c_str(), L"r, ccs=UTF-8");
    if (!fp) { wprintf(L"quarantine is empty (%ls)\n", quarantineDir().c_str()); return; }
    wchar_t line[4096];
    wprintf(L"== quarantine manifest (%ls) ==\n", quarantineDir().c_str());
    while (fgetws(line, 4096, fp)) fputws(line, stdout);
    fclose(fp);
}

// Restore by quarantine id, using the manifest to find the original path.
static bool restoreQuarantine(const std::wstring& id) {
    std::wstring mf = quarantineDir() + L"\\manifest.txt";
    FILE* fp = _wfopen(mf.c_str(), L"r, ccs=UTF-8");
    if (!fp) { wprintf(L"[!] no quarantine manifest\n"); return false; }
    std::wstring orig;
    wchar_t line[4096];
    while (fgetws(line, 4096, fp)) {
        std::wstring s(line);
        // fields: time \t id \t original path \t hash \t score
        size_t t1 = s.find(L'\t');
        if (t1 == std::wstring::npos) continue;
        size_t t2 = s.find(L'\t', t1 + 1);
        if (t2 == std::wstring::npos) continue;
        if (s.substr(t1 + 1, t2 - t1 - 1) != id) continue;
        size_t t3 = s.find(L'\t', t2 + 1);
        orig = s.substr(t2 + 1, t3 == std::wstring::npos ? std::wstring::npos : t3 - t2 - 1);
        // last match wins, so a re-quarantined file restores to where it last was
    }
    fclose(fp);
    if (orig.empty()) { wprintf(L"[!] id not found in manifest: %ls\n", id.c_str()); return false; }
    std::wstring src = quarantineDir() + L"\\" + id;
    if (!MoveFileExW(src.c_str(), orig.c_str(), 0)) {
        wprintf(L"[!] restore failed (error %lu): %ls -> %ls\n", GetLastError(), src.c_str(), orig.c_str());
        return false;
    }
    wprintf(L"restored %ls -> %ls\n", id.c_str(), orig.c_str());
    return true;
}

// ------------------------------------------------------------ ClamAV hand-off
// Rescue does not vendor libclamav (MSVC/autotools C, does not cross-compile
// with MinGW). If the operator has a real ClamAV install, its engine and its
// daily-updated signatures are strictly better than anything here, so we hand
// the flagged files to it and print what it says.
static bool haveTool(const wchar_t* exe, std::wstring& resolved) {
    wchar_t buf[MAX_PATH * 2];
    wcsncpy(buf, exe, MAX_PATH);
    buf[MAX_PATH] = 0;
    if (PathFindOnPathW(buf, nullptr)) { resolved = buf; return true; }
    return false;
}

static void clamScan(const std::vector<Finding>& findings) {
    std::wstring tool;
    bool daemon = haveTool(L"clamdscan.exe", tool);
    if (!daemon && !haveTool(L"clamscan.exe", tool)) {
        wprintf(L"\n[i] --clam: no clamdscan/clamscan on PATH; skipping engine scan.\n"
                L"    Install ClamAV for Windows and re-run to get signature-based verdicts.\n");
        return;
    }
    wprintf(L"\n== ClamAV engine pass (%ls) ==\n", tool.c_str());
    for (const Finding& f : findings) {
        std::wstring cmd = L"\"" + tool + L"\" --no-summary \"" + f.path + L"\"";
        std::vector<wchar_t> buf(cmd.begin(), cmd.end());
        buf.push_back(0);
        STARTUPINFOW si{}; si.cb = sizeof(si);
        PROCESS_INFORMATION pi{};
        if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE,
                            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
            wprintf(L"  [!] could not run %ls\n", tool.c_str());
            return;
        }
        WaitForSingleObject(pi.hProcess, 120000);
        DWORD rc = 0;
        GetExitCodeProcess(pi.hProcess, &rc);
        CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        // clamscan: 0 = clean, 1 = virus found, 2 = error.
        wprintf(L"  %ls  %ls\n", rc == 1 ? L"INFECTED" : rc == 0 ? L"clean   " : L"error   ",
                f.path.c_str());
    }
}

// -------------------------------------------------------------- traversal --
static std::vector<Finding> g_findings;

static void printFinding(const Finding& f) {
    const wchar_t* band = f.known ? L"KNOWN-BAD" : f.score >= 8 ? L"HIGH " : L"WATCH";
    wprintf(L"\n[%ls] score %d  %ls\n", band, f.score, f.path.c_str());
    wprintf(L"        sha256 %ls   <%ls%ls%ls>\n", f.hash.c_str(), sig::TrustName(f.trust),
            f.signer.empty() ? L"" : L" - ", f.signer.c_str());
    for (auto& r : f.reasons) wprintf(L"        - %ls\n", r.c_str());
}

static bool skipDirectory(const std::wstring& lowPath) {
    // WinSxS and the driver store are enormous, catalog-signed, and would
    // dominate a full scan's runtime for no yield. Everything else in \Windows
    // is still walked - that is where a masquerading binary would hide.
    return inAnyOf(lowPath, { L"\\windows\\winsxs", L"\\windows\\servicing",
                              L"\\windows\\assembly", L"\\system volume information",
                              L"\\windows\\softwaredistribution" });
}

static void walk(const std::wstring& dir, int depth) {
    if (depth > 24) return;
    std::wstring low = lower(dir);
    if (skipDirectory(low)) return;

    WIN32_FIND_DATAW fd;
    HANDLE h = FindFirstFileW((dir + L"\\*").c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        if (!wcscmp(fd.cFileName, L".") || !wcscmp(fd.cFileName, L"..")) continue;
        // Never follow reparse points: junctions loop, and a symlinked share
        // would silently pull a network scan into a local one.
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) continue;
        std::wstring full = dir + L"\\" + fd.cFileName;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            walk(full, depth + 1);
        } else {
            Finding f;
            if (scanFile(full, f)) {
                ++g_detections;
                printFinding(f);
                if (g_quarantine && quarantineFile(f)) ++g_quarantined;
                g_findings.push_back(std::move(f));
            }
        }
    } while (FindNextFileW(h, &fd));
    FindClose(h);
}

// The quick scan targets where droppers actually land, rather than pretending
// to be exhaustive: downloads, temp, roaming, public, startup folders.
static std::vector<std::wstring> quickTargets() {
    std::vector<std::wstring> t;
    std::wstring up = envPath(L"USERPROFILE");
    std::wstring ad = envPath(L"APPDATA");
    std::wstring lad = envPath(L"LOCALAPPDATA");
    std::wstring pd = envPath(L"ProgramData");
    std::wstring wd = envPath(L"SystemRoot");
    if (!up.empty()) {
        t.push_back(up + L"\\Downloads");
        t.push_back(up + L"\\Desktop");
        t.push_back(up + L"\\Documents");
    }
    if (!lad.empty()) { t.push_back(lad + L"\\Temp"); }
    if (!ad.empty())  { t.push_back(ad + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"); }
    if (!pd.empty())  { t.push_back(pd + L"\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp"); }
    if (!wd.empty())  { t.push_back(wd + L"\\Temp"); }
    std::wstring pub = envPath(L"PUBLIC");
    if (!pub.empty()) t.push_back(pub);
    return t;
}

static std::vector<std::wstring> fullTargets() {
    std::vector<std::wstring> t;
    wchar_t drives[512]{};
    DWORD n = GetLogicalDriveStringsW(511, drives);
    for (wchar_t* p = drives; p < drives + n && *p; p += wcslen(p) + 1) {
        if (GetDriveTypeW(p) != DRIVE_FIXED) continue;   // no network/removable sweep
        std::wstring d(p);
        while (!d.empty() && (d.back() == L'\\' || d.back() == L'/')) d.pop_back();
        t.push_back(d);
    }
    return t;
}

// ------------------------------------------------------- scheduled scans ---
// schtasks is the documented way to register a scheduled task without shipping
// a COM task-scheduler dependency; the task runs the same binary that created
// it, elevated, as SYSTEM.
static bool scheduleDaily(const std::wstring& hhmm) {
    wchar_t self[MAX_PATH * 2];
    if (!GetModuleFileNameW(nullptr, self, MAX_PATH * 2)) return false;
    std::wstring cmd = L"schtasks /Create /F /SC DAILY /ST " + hhmm +
                       L" /RU SYSTEM /RL HIGHEST /TN \"Rescue Daily Scan\" /TR "
                       L"\"\\\"" + self + L"\\\" --quiet\"";
    std::vector<wchar_t> buf(cmd.begin(), cmd.end());
    buf.push_back(0);
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, buf.data(), nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD rc = 1; GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return rc == 0;
}

static bool unschedule() {
    wchar_t cmd[] = L"schtasks /Delete /F /TN \"Rescue Daily Scan\"";
    STARTUPINFOW si{}; si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, cmd, nullptr, nullptr, FALSE, 0, nullptr, nullptr, &si, &pi))
        return false;
    WaitForSingleObject(pi.hProcess, 30000);
    DWORD rc = 1; GetExitCodeProcess(pi.hProcess, &rc);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
    return rc == 0;
}

// ------------------------------------------------------------------- main --
static void usage() {
    wprintf(
        L"Rescue Scanner - heuristic + hash file scanner (report-only by default)\n\n"
        L"  scanner                      quick scan: Downloads, Desktop, Documents,\n"
        L"                               Temp, Roaming, Public, startup folders\n"
        L"  scanner --full               every fixed drive (skips WinSxS/servicing)\n"
        L"  scanner --path DIR|FILE      scan a specific path (repeatable)\n"
        L"  scanner --db HASHES.txt      SHA-256 blocklist (one hex hash per line)\n"
        L"  scanner --min-score N        report threshold (default 4; >=8 is HIGH)\n"
        L"  scanner --clam               also run a local ClamAV over the detections\n"
        L"  scanner --quarantine         move detections aside (reversible)\n"
        L"  scanner --list-quarantine    show what has been quarantined\n"
        L"  scanner --restore ID         put a quarantined file back\n"
        L"  scanner --schedule-daily HH:MM   register a daily scheduled scan\n"
        L"  scanner --unschedule         remove the scheduled scan\n\n"
        L"A score is a ranking for a human, not a verdict. Only a hash blocklist\n"
        L"match (KNOWN-BAD) is a fact; everything else is a weighted heuristic.\n");
}

int wmain(int argc, wchar_t** argv) {
    bool quiet = false;
    for (int i = 1; i < argc; ++i) {
        std::wstring a = argv[i];
        if (a == L"--help" || a == L"-h") { usage(); return 0; }
        else if (a == L"--full") g_full = true;
        else if (a == L"--quarantine") g_quarantine = true;
        else if (a == L"--clam") g_clam = true;
        else if (a == L"--quiet") quiet = true;
        else if (a == L"--list-quarantine") { listQuarantine(); return 0; }
        else if (a == L"--restore" && i + 1 < argc) return restoreQuarantine(argv[++i]) ? 0 : 1;
        else if (a == L"--path" && i + 1 < argc) g_paths.push_back(argv[++i]);
        else if (a == L"--db" && i + 1 < argc) g_db = argv[++i];
        else if (a == L"--min-score" && i + 1 < argc) g_minScore = _wtoi(argv[++i]);
        else if (a == L"--schedule-daily" && i + 1 < argc) {
            bool ok = scheduleDaily(argv[++i]);
            wprintf(ok ? L"daily scan scheduled.\n" : L"[!] scheduling failed (run elevated).\n");
            return ok ? 0 : 1;
        }
        else if (a == L"--unschedule") {
            bool ok = unschedule();
            wprintf(ok ? L"scheduled scan removed.\n" : L"[!] removal failed.\n");
            return ok ? 0 : 1;
        }
        else { wprintf(L"unknown option: %ls\n\n", a.c_str()); usage(); return 2; }
    }

    if (!quiet) {
        wprintf(L"Rescue Scanner\n");
        if (!priv::IsElevated())
            wprintf(L"[!] not elevated - files outside your profile will be unreadable.\n");
    }
    // SYSTEM lets the scanner read protected directories and quarantine files
    // whose ACLs a plain admin cannot touch. Best-effort: the scan still runs
    // without it, just with less reach.
    priv::EnableDebugPrivilege();
    priv::ImpersonateSystem();

    if (!g_db.empty()) loadBlocklist(g_db);

    std::vector<std::wstring> targets = g_paths;
    if (targets.empty()) targets = g_full ? fullTargets() : quickTargets();

    DWORD t0 = GetTickCount();
    for (const std::wstring& t : targets) {
        DWORD attr = GetFileAttributesW(t.c_str());
        if (attr == INVALID_FILE_ATTRIBUTES) continue;
        if (!quiet) wprintf(L"\n== scanning %ls ==\n", t.c_str());
        if (attr & FILE_ATTRIBUTE_DIRECTORY) {
            walk(t, 0);
        } else {
            Finding f;
            if (scanFile(t, f)) {
                ++g_detections;
                printFinding(f);
                if (g_quarantine && quarantineFile(f)) ++g_quarantined;
                g_findings.push_back(std::move(f));
            }
        }
    }

    if (g_clam && !g_findings.empty()) clamScan(g_findings);
    priv::Revert();

    wprintf(L"\n== summary ==\n");
    wprintf(L"  files inspected   : %lld\n", g_scanned);
    wprintf(L"  cleared by signature: %lld\n", g_skippedTrusted);
    wprintf(L"  flagged (score >= %d): %lld\n", g_minScore, g_detections);
    if (g_quarantine) wprintf(L"  quarantined       : %lld\n", g_quarantined);
    wprintf(L"  elapsed           : %.1f s\n", (GetTickCount() - t0) / 1000.0);
    if (g_detections && !g_quarantine)
        wprintf(L"\nReview the findings above. Re-run with --quarantine to move them aside\n"
                L"(reversible: scanner --list-quarantine / --restore ID).\n");
    return g_detections ? 1 : 0;
}
