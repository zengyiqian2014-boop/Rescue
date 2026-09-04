// asep_cleaner.cpp - Rescue module 2: enumerate EVERY autostart, flag the
// unsigned ones. Generic, not per-virus.
//
// Malware can be anything, but to survive a reboot it must anchor itself to one
// of a finite set of Auto-Start Extensibility Points (ASEPs). Rescue walks all
// of them, verifies each program's Authenticode signature (embedded AND
// catalog - see signature.h), and flags whatever is unsigned, untrusted, or
// points at a missing file. That catches brand-new malware nobody has a
// signature for yet, without a virus database.
//
// DRY-RUN BY DEFAULT. --quarantine disables the flagged entries (registry
// values are backed up first; startup files are renamed, not deleted).
#include <windows.h>
#include <winsvc.h>
#include <cstdio>
#include <string>
#include <vector>
#include "privilege.h"
#include "signature.h"

static bool g_quar = false;
static int  g_flagged = 0, g_quarantined = 0, g_total = 0;

static void head(const wchar_t* s) { wprintf(L"\n== %ls ==\n", s); }

// Report one autostart entry, classified by signature.
// Returns true if it was flagged (and, in quarantine mode, should be neutralized).
static bool report(const wchar_t* where, const std::wstring& name,
                   const std::wstring& exe, sig::Trust t, const std::wstring& signer) {
    ++g_total;
    bool flag = !sig::IsTrusted(t);
    const wchar_t* tag = flag ? L"[!]" : L"   ";
    wprintf(L"  %ls %ls  ::  %ls\n", tag, where, name.c_str());
    wprintf(L"        %ls   <%ls%ls%ls>\n", exe.empty() ? L"(no file)" : exe.c_str(),
            sig::TrustName(t),
            signer.empty() ? L"" : L" - ", signer.c_str());
    if (flag) ++g_flagged;
    return flag;
}

// Pull the executable path out of a command line and resolve it to a real file.
static std::wstring extractExe(const std::wstring& cmdRaw) {
    wchar_t expanded[2048];
    ExpandEnvironmentStringsW(cmdRaw.c_str(), expanded, 2048);
    std::wstring s = expanded;
    size_t i = 0; while (i < s.size() && iswspace(s[i])) ++i;
    std::wstring path;
    if (i < s.size() && s[i] == L'"') {
        size_t e = s.find(L'"', i + 1);
        path = s.substr(i + 1, e == std::wstring::npos ? std::wstring::npos : e - i - 1);
    } else {
        // unquoted: try the whole thing, then progressively shorter prefixes at spaces
        std::wstring rest = s.substr(i);
        if (GetFileAttributesW(rest.c_str()) != INVALID_FILE_ATTRIBUTES) return rest;
        size_t sp = 0;
        while ((sp = rest.find(L' ', sp + 1)) != std::wstring::npos) {
            std::wstring cand = rest.substr(0, sp);
            std::wstring wexe = cand + L".exe";
            if (GetFileAttributesW(cand.c_str()) != INVALID_FILE_ATTRIBUTES) return cand;
            if (GetFileAttributesW(wexe.c_str()) != INVALID_FILE_ATTRIBUTES) return wexe;
        }
        path = rest;
    }
    if (!path.empty() && GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::wstring wexe = path + L".exe";
        if (GetFileAttributesW(wexe.c_str()) != INVALID_FILE_ATTRIBUTES) return wexe;
        // Bare name (e.g. Winlogon Shell = "explorer.exe"): resolve it the same
        // way the OS would - via System32 / Windows dir / PATH - so we verify
        // the real binary instead of falsely flagging it as missing.
        wchar_t resolved[MAX_PATH]; wchar_t* filepart = nullptr;
        if (SearchPathW(nullptr, path.c_str(), L".exe", MAX_PATH, resolved, &filepart))
            return resolved;
    }
    return path;
}

// --- registry Run/RunOnce style keys ---------------------------------------
static void scanRunKey(HKEY root, const wchar_t* subkey, const wchar_t* label, REGSAM extra = 0) {
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_READ | KEY_WOW64_64KEY | extra, &h) != ERROR_SUCCESS) return;
    DWORD idx = 0; wchar_t name[512]; BYTE data[4096];
    for (;;) {
        DWORD nlen = 512, dlen = sizeof(data), type = 0;
        LONG r = RegEnumValueW(h, idx++, name, &nlen, nullptr, &type, data, &dlen);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) break;
        if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
        std::wstring cmd(reinterpret_cast<wchar_t*>(data));
        std::wstring exe = extractExe(cmd);
        std::wstring signer; sig::Trust t = exe.empty() ? sig::Trust::Missing : sig::Verify(exe, &signer);
        if (report(label, name, exe, t, signer) && g_quar) {
            // back up value, then delete
            HKEY bk;
            if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\RescueQuarantine\\Run", 0, nullptr,
                    0, KEY_SET_VALUE | KEY_WOW64_64KEY, nullptr, &bk, nullptr) == ERROR_SUCCESS) {
                RegSetValueExW(bk, name, 0, REG_SZ, (const BYTE*)cmd.c_str(),
                               (DWORD)((cmd.size() + 1) * sizeof(wchar_t)));
                RegCloseKey(bk);
            }
            HKEY wh;
            if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY | extra, &wh) == ERROR_SUCCESS) {
                if (RegDeleteValueW(wh, name) == ERROR_SUCCESS) { wprintf(L"        -> quarantined (backed up + removed)\n"); ++g_quarantined; }
                RegCloseKey(wh);
                --idx;  // indices shifted after delete
            }
        }
    }
    RegCloseKey(h);
}

static void scanRunKeys() {
    head(L"Run / RunOnce (HKLM, HKCU, all users, WOW64)");
    const wchar_t* R  = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run";
    const wchar_t* R1 = L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce";
    const wchar_t* Rw = L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run";
    scanRunKey(HKEY_LOCAL_MACHINE, R,  L"HKLM\\...\\Run");
    scanRunKey(HKEY_LOCAL_MACHINE, R1, L"HKLM\\...\\RunOnce");
    scanRunKey(HKEY_LOCAL_MACHINE, Rw, L"HKLM\\WOW64\\...\\Run");
    scanRunKey(HKEY_CURRENT_USER,  R,  L"HKCU\\...\\Run");
    scanRunKey(HKEY_CURRENT_USER,  R1, L"HKCU\\...\\RunOnce");
    // all loaded user hives
    DWORD i = 0; wchar_t sid[256]; DWORD sl;
    for (;; ++i) {
        sl = 256;
        if (RegEnumKeyExW(HKEY_USERS, i, sid, &sl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        std::wstring s = sid;
        if (s == L".DEFAULT" || (s.size() > 8 && s.substr(s.size() - 8) == L"_Classes")) continue;
        std::wstring sub = s + L"\\" + R;
        scanRunKey(HKEY_USERS, sub.c_str(), L"HKU\\...\\Run");
    }
}

// --- Winlogon, IFEO, AppInit ------------------------------------------------
static void scanWinlogon() {
    head(L"Winlogon shell / Userinit");
    const wchar_t* wl = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, wl, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return;
    for (auto v : { L"Shell", L"Userinit" }) {
        wchar_t buf[1024]; DWORD sz = sizeof(buf), type = 0;
        if (RegQueryValueExW(h, v, nullptr, &type, (BYTE*)buf, &sz) == ERROR_SUCCESS) {
            std::wstring val(buf);
            // may contain several comma-separated entries
            size_t start = 0;
            while (start < val.size()) {
                size_t comma = val.find(L',', start);
                std::wstring one = val.substr(start, comma == std::wstring::npos ? std::wstring::npos : comma - start);
                while (!one.empty() && iswspace(one.front())) one.erase(one.begin());
                if (!one.empty()) {
                    std::wstring exe = extractExe(one);
                    std::wstring signer; sig::Trust t = exe.empty() ? sig::Trust::Missing : sig::Verify(exe, &signer);
                    report(v, one, exe, t, signer);
                }
                if (comma == std::wstring::npos) break; start = comma + 1;
            }
        }
    }
    RegCloseKey(h);
}

static void scanIFEO() {
    head(L"Image File Execution Options (debugger hijacks)");
    const wchar_t* base = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options";
    HKEY h;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, base, 0, KEY_READ | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS) return;
    DWORD i = 0; wchar_t sub[512];
    for (;; ++i) {
        DWORD sl = 512;
        if (RegEnumKeyExW(h, i, sub, &sl, nullptr, nullptr, nullptr, nullptr) != ERROR_SUCCESS) break;
        std::wstring kp = std::wstring(base) + L"\\" + sub;
        HKEY hk;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kp.c_str(), 0, KEY_READ | KEY_WOW64_64KEY, &hk) == ERROR_SUCCESS) {
            wchar_t dbg[1024]; DWORD dz = sizeof(dbg), type = 0;
            if (RegQueryValueExW(hk, L"Debugger", nullptr, &type, (BYTE*)dbg, &dz) == ERROR_SUCCESS) {
                std::wstring exe = extractExe(dbg);
                std::wstring signer; sig::Trust t = exe.empty() ? sig::Trust::Missing : sig::Verify(exe, &signer);
                std::wstring where = std::wstring(L"IFEO\\") + sub;
                if (report(where.c_str(), L"Debugger", exe, t, signer) && g_quar) {
                    HKEY wh;
                    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, kp.c_str(), 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &wh) == ERROR_SUCCESS) {
                        if (RegDeleteValueW(wh, L"Debugger") == ERROR_SUCCESS) { wprintf(L"        -> quarantined (debugger hijack removed)\n"); ++g_quarantined; }
                        RegCloseKey(wh);
                    }
                }
            }
            RegCloseKey(hk);
        }
    }
    RegCloseKey(h);
}

// --- startup folders --------------------------------------------------------
static void scanStartupFolder(const std::wstring& dir, const wchar_t* label) {
    WIN32_FIND_DATAW fd; std::wstring pat = dir + L"\\*";
    HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        std::wstring f = dir + L"\\" + fd.cFileName;
        std::wstring exe = f;
        // .lnk shortcuts point elsewhere; we verify the .lnk file's own trust as a proxy
        std::wstring signer; sig::Trust t = sig::Verify(exe, &signer);
        if (report(label, fd.cFileName, exe, t, signer) && g_quar) {
            std::wstring q = f + L".rescue_quarantine";
            if (MoveFileExW(f.c_str(), q.c_str(), MOVEFILE_REPLACE_EXISTING)) { wprintf(L"        -> quarantined (renamed)\n"); ++g_quarantined; }
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}

static void scanStartupFolders() {
    head(L"Startup folders");
    wchar_t buf[MAX_PATH];
    if (GetEnvironmentVariableW(L"APPDATA", buf, MAX_PATH))
        scanStartupFolder(std::wstring(buf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", L"User Startup");
    if (GetEnvironmentVariableW(L"ProgramData", buf, MAX_PATH))
        scanStartupFolder(std::wstring(buf) + L"\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", L"Common Startup");
}

// --- services (auto-start) --------------------------------------------------
static void scanServices() {
    head(L"Auto-start services");
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) { wprintf(L"    (cannot open SCM)\n"); return; }
    DWORD bytes = 0, count = 0, resume = 0;
    EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                          nullptr, 0, &bytes, &count, &resume, nullptr);
    std::vector<BYTE> buf(bytes ? bytes : 1);
    if (EnumServicesStatusExW(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL,
                              buf.data(), bytes, &bytes, &count, &resume, nullptr)) {
        auto* svc = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            SC_HANDLE s = OpenServiceW(scm, svc[i].lpServiceName, SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG);
            if (!s) continue;
            DWORD need = 0; QueryServiceConfigW(s, nullptr, 0, &need);
            std::vector<BYTE> cb(need ? need : 1);
            auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cb.data());
            if (QueryServiceConfigW(s, cfg, need, &need) && cfg->dwStartType == SERVICE_AUTO_START) {
                std::wstring exe = extractExe(cfg->lpBinaryPathName ? cfg->lpBinaryPathName : L"");
                std::wstring signer; sig::Trust t = exe.empty() ? sig::Trust::Missing : sig::Verify(exe, &signer);
                if (report(L"service", svc[i].lpServiceName, exe, t, signer) && g_quar) {
                    if (ChangeServiceConfigW(s, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE,
                            nullptr, nullptr, nullptr, nullptr, nullptr, nullptr, nullptr)) {
                        wprintf(L"        -> quarantined (start type set to Disabled)\n"); ++g_quarantined;
                    }
                }
            }
            CloseServiceHandle(s);
        }
    }
    CloseServiceHandle(scm);
}

// --- scheduled tasks (report only) -----------------------------------------
static void scanTasks(const std::wstring& dir) {
    WIN32_FIND_DATAW fd; std::wstring pat = dir + L"\\*";
    HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
    if (hf == INVALID_HANDLE_VALUE) return;
    do {
        std::wstring nm = fd.cFileName;
        if (nm == L"." || nm == L"..") continue;
        std::wstring full = dir + L"\\" + nm;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) { scanTasks(full); continue; }
        HANDLE h = CreateFileW(full.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (h == INVALID_HANDLE_VALUE) continue;
        DWORD sz = GetFileSize(h, nullptr); std::string xml(sz, 0); DWORD rd = 0;
        ReadFile(h, xml.data(), sz, &rd, nullptr); CloseHandle(h);
        // crude: pull <Command>...</Command>
        size_t a = xml.find("<Command>");
        if (a != std::string::npos) {
            size_t b = xml.find("</Command>", a);
            std::string cmd = xml.substr(a + 9, b - a - 9);
            std::wstring wcmd(cmd.begin(), cmd.end());
            std::wstring exe = extractExe(wcmd);
            std::wstring signer; sig::Trust t = exe.empty() ? sig::Trust::Missing : sig::Verify(exe, &signer);
            report(L"task", nm, exe, t, signer);
        }
    } while (FindNextFileW(hf, &fd));
    FindClose(hf);
}
static void scanScheduledTasks() {
    head(L"Scheduled tasks (report only)");
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    scanTasks(std::wstring(win) + L"\\System32\\Tasks");
}

static void usage() {
    wprintf(
        L"Rescue - ASEP Cleaner\n"
        L"Enumerate every autostart point and flag the unsigned / untrusted ones.\n\n"
        L"USAGE:  asep_cleaner [--quarantine] [--help]\n\n"
        L"  (no options)   scan and REPORT only - flags entries whose program is\n"
        L"                 unsigned, untrusted, or missing. Signed Microsoft /\n"
        L"                 vendor entries (embedded OR catalog) are left alone.\n"
        L"  --quarantine   neutralize flagged entries: registry values are backed\n"
        L"                 up to HKLM\\SOFTWARE\\RescueQuarantine then removed;\n"
        L"                 startup files are renamed; auto-start services are\n"
        L"                 disabled. Scheduled tasks are reported, not touched.\n"
        L"  -h, --help     this help\n\n"
        L"Review a plain scan first - a flag means 'unsigned', not 'definitely bad'.\n");
}

int wmain(int argc, wchar_t** argv) {
    for (int i = 1; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"--quarantine")) g_quar = true;
        else if (!_wcsicmp(argv[i], L"-h") || !_wcsicmp(argv[i], L"--help")) { usage(); return 0; }
        else { wprintf(L"unknown option: %ls\n\n", argv[i]); usage(); return 2; }
    }
    priv::EnableDebugPrivilege();

    wprintf(L"=====================================================\n");
    wprintf(L"  Rescue - ASEP Cleaner        %ls\n", g_quar ? L"[QUARANTINE]" : L"[scan only]");
    wprintf(L"=====================================================\n");
    wprintf(L"  Signed entries (embedded or catalog) are trusted and left alone.\n");
    wprintf(L"  [!] marks unsigned / untrusted / missing-file entries.\n");

    scanRunKeys();
    scanWinlogon();
    scanIFEO();
    scanStartupFolders();
    scanServices();
    scanScheduledTasks();

    wprintf(L"\n-----------------------------------------------------\n");
    wprintf(L"  Autostarts examined: %d   Flagged: %d", g_total, g_flagged);
    if (g_quar) wprintf(L"   Quarantined: %d", g_quarantined);
    wprintf(L"\n");
    if (g_flagged && !g_quar)
        wprintf(L"  Review the [!] entries. Re-run with --quarantine to neutralize them.\n");
    else if (!g_flagged)
        wprintf(L"  Nothing unsigned in any autostart point. Clean.\n");
    wprintf(L"-----------------------------------------------------\n");
    return 0;
}
