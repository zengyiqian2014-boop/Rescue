// lockdown_breaker.cpp - Rescue module 1: actively undo a malware lockdown.
//
// Malware that locks you out of your own machine does it with a small, finite
// set of levers: restriction *policies* in the registry (Task Manager, regedit,
// cmd, the desktop, drives), a hijacked login *shell*, a frozen input queue
// (BlockInput), a full-screen "you are locked" *overlay* window, and - the new
// trick - a dropped Code-Integrity / WDAC policy that blocks .exe launches.
//
// This tool walks every one of those levers, REPORTS what it finds, and (with
// --fix) puts it back to the OS default. It is deliberately dry-run by default:
// it never changes anything until you pass --fix.
//
// Scope note: this is the *online* breaker for the live system. A Microsoft-
// signed / boot-anchored WDAC policy usually cannot be cleared while the OS is
// enforcing it - for that, use the offline WinPE rescue (roadmap Phase 1b).
// This tool will still back it up, attempt removal, and tell you if you must go
// offline.
#include <windows.h>
#include <shlwapi.h>
#include <cstdio>
#include <string>
#include <vector>
#include "privilege.h"

// ---------------------------------------------------------------------------
// small console helpers
// ---------------------------------------------------------------------------
static int g_findings = 0;
static int g_fixed = 0;
static bool g_fix = false;

static void info(const wchar_t* s)  { wprintf(L"    %ls\n", s); }
static void head(const wchar_t* s)  { wprintf(L"\n== %ls ==\n", s); }
static void found(const wchar_t* fmt, const wchar_t* a) {
    wprintf(L"  [!] "); wprintf(fmt, a); wprintf(L"\n"); ++g_findings;
}
static void done(const wchar_t* msg) { wprintf(L"      -> %ls\n", msg); }

// ---------------------------------------------------------------------------
// registry helpers (always 64-bit view)
// ---------------------------------------------------------------------------
static bool RegHasValue(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    LONG r = RegQueryValueExW(h, value, nullptr, nullptr, nullptr, nullptr);
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

static bool RegDeleteValueSafe(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    LONG r = RegDeleteValueW(h, value);
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

static std::wstring RegReadString(HKEY root, const wchar_t* subkey, const wchar_t* value) {
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return L"";
    wchar_t buf[1024]; DWORD sz = sizeof(buf), type = 0;
    std::wstring out;
    if (RegQueryValueExW(h, value, nullptr, &type, (LPBYTE)buf, &sz) == ERROR_SUCCESS &&
        (type == REG_SZ || type == REG_EXPAND_SZ)) {
        buf[(sz / sizeof(wchar_t)) < 1024 ? (sz / sizeof(wchar_t)) : 1023] = 0;
        out = buf;
    }
    RegCloseKey(h);
    return out;
}

static bool RegWriteString(HKEY root, const wchar_t* subkey, const wchar_t* value,
                           const wchar_t* data) {
    HKEY h;
    if (RegOpenKeyExW(root, subkey, 0, KEY_SET_VALUE | KEY_WOW64_64KEY, &h) != ERROR_SUCCESS)
        return false;
    LONG r = RegSetValueExW(h, value, 0, REG_SZ, (const BYTE*)data,
                            (DWORD)((wcslen(data) + 1) * sizeof(wchar_t)));
    RegCloseKey(h);
    return r == ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// the finite set of restriction levers malware flips
// ---------------------------------------------------------------------------
struct PolItem { const wchar_t* subkey; const wchar_t* value; const wchar_t* what; };

// Per-user policies (subkey is relative to a user hive under HKEY_USERS).
static const PolItem kUserPolicies[] = {
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableTaskMgr",        L"Task Manager disabled"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableRegistryTools",  L"regedit disabled"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableChangePassword", L"Change-password disabled"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableLockWorkstation",L"Lock (Win+L) disabled"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoRun",                 L"Run box removed"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoDesktop",             L"Desktop icons hidden"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoControlPanel",        L"Control Panel blocked"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoViewContextMenu",     L"Right-click menu blocked"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoFind",                L"Search blocked"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoClose",               L"Shut-down blocked"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoFolderOptions",       L"Folder Options blocked"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoDrives",              L"Drives hidden"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"RestrictRun",           L"Only whitelisted apps may run"},
    {L"Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"DisallowRun",           L"Blacklisted apps blocked"},
    {L"Software\\Policies\\Microsoft\\Windows\\System",                   L"DisableCMD",            L"Command Prompt disabled"},
};

// Machine-wide policies (subkey relative to HKLM).
static const PolItem kMachinePolicies[] = {
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableTaskMgr",        L"Task Manager disabled (all users)"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",   L"DisableRegistryTools",  L"regedit disabled (all users)"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoRun",                 L"Run box removed (all users)"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoDesktop",             L"Desktop icons hidden (all users)"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"NoControlPanel",        L"Control Panel blocked (all users)"},
    {L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer", L"RestrictRun",           L"Only whitelisted apps may run (all users)"},
    {L"SOFTWARE\\Policies\\Microsoft\\Windows\\System",                   L"DisableCMD",            L"Command Prompt disabled (all users)"},
};

static void scanPolicySet(HKEY root, const std::wstring& prefix,
                          const PolItem* items, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        std::wstring sub = prefix + items[i].subkey;
        if (RegHasValue(root, sub.c_str(), items[i].value)) {
            found(L"%ls", items[i].what);
            if (g_fix) {
                if (RegDeleteValueSafe(root, sub.c_str(), items[i].value)) { done(L"cleared"); ++g_fixed; }
                else done(L"could NOT clear (need higher privilege / offline)");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// per-user hives: enumerate HKEY_USERS
// ---------------------------------------------------------------------------
static void scanAllUserHives() {
    head(L"Per-user restriction policies (all logged-on users)");
    DWORD idx = 0; wchar_t sid[256]; DWORD sidLen;
    for (;; ++idx) {
        sidLen = 256;
        LONG r = RegEnumKeyExW(HKEY_USERS, idx, sid, &sidLen, nullptr, nullptr, nullptr, nullptr);
        if (r == ERROR_NO_MORE_ITEMS) break;
        if (r != ERROR_SUCCESS) break;
        std::wstring s = sid;
        if (s == L".DEFAULT") continue;
        if (s.size() > 8 && s.substr(s.size() - 8) == L"_Classes") continue;
        scanPolicySet(HKEY_USERS, s + L"\\", kUserPolicies,
                      sizeof(kUserPolicies) / sizeof(kUserPolicies[0]));
    }
}

// ---------------------------------------------------------------------------
// login shell hijack (Winlogon\Shell, Userinit)
// ---------------------------------------------------------------------------
static void scanShellHijack() {
    head(L"Login shell / Userinit hijack");
    const wchar_t* wl = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon";
    std::wstring shell = RegReadString(HKEY_LOCAL_MACHINE, wl, L"Shell");
    if (!shell.empty() && _wcsicmp(shell.c_str(), L"explorer.exe") != 0) {
        found(L"Shell hijacked to: %ls", shell.c_str());
        if (g_fix) {
            if (RegWriteString(HKEY_LOCAL_MACHINE, wl, L"Shell", L"explorer.exe")) { done(L"restored to explorer.exe"); ++g_fixed; }
            else done(L"could NOT restore");
        }
    }
    std::wstring ui = RegReadString(HKEY_LOCAL_MACHINE, wl, L"Userinit");
    const wchar_t* def = L"C:\\Windows\\system32\\userinit.exe,";
    if (!ui.empty() && !StrStrIW(ui.c_str(), L"userinit.exe")) {
        found(L"Userinit hijacked to: %ls", ui.c_str());
        if (g_fix) {
            if (RegWriteString(HKEY_LOCAL_MACHINE, wl, L"Userinit", def)) { done(L"restored to default"); ++g_fixed; }
            else done(L"could NOT restore");
        }
    }
}

// ---------------------------------------------------------------------------
// frozen input (BlockInput) - only fixable, not detectable; unfreeze on --fix
// ---------------------------------------------------------------------------
static void unfreezeInput() {
    head(L"Frozen keyboard/mouse (BlockInput)");
    if (g_fix) {
        // A higher-privilege process can always release another's BlockInput.
        // This is an unconditional safety action, not tied to a detected
        // finding, so it does not count toward the fixed/findings tally.
        BlockInput(FALSE);
        done(L"BlockInput(FALSE) issued - input released if it was frozen");
    } else {
        info(L"(run with --fix to force-release any BlockInput lock)");
    }
}

// ---------------------------------------------------------------------------
// full-screen "locked" overlay windows
// ---------------------------------------------------------------------------
struct OverlayCtx { bool kill; };
static BOOL CALLBACK enumOverlays(HWND hwnd, LPARAM lp) {
    auto* ctx = reinterpret_cast<OverlayCtx*>(lp);
    if (!IsWindowVisible(hwnd)) return TRUE;
    RECT r; if (!GetWindowRect(hwnd, &r)) return TRUE;
    int w = r.right - r.left, h = r.bottom - r.top;
    int sw = GetSystemMetrics(SM_CXSCREEN), sh = GetSystemMetrics(SM_CYSCREEN);
    LONG ex = GetWindowLongW(hwnd, GWL_EXSTYLE);
    bool topmost = (ex & WS_EX_TOPMOST) != 0;
    bool fullish = w >= sw - 8 && h >= sh - 8;   // covers (near) the whole screen
    if (!(topmost && fullish)) return TRUE;
    wchar_t cls[128] = {0}, title[256] = {0};
    GetClassNameW(hwnd, cls, 128);
    GetWindowTextW(hwnd, title, 256);
    // The real desktop/shell also owns full-screen topmost windows - never touch those.
    if (_wcsicmp(cls, L"Progman") == 0 || _wcsicmp(cls, L"WorkerW") == 0 ||
        _wcsicmp(cls, L"Shell_TrayWnd") == 0) return TRUE;
    DWORD pid = 0; GetWindowThreadProcessId(hwnd, &pid);
    wchar_t line[512];
    swprintf(line, 512, L"full-screen topmost overlay  class=\"%ls\" title=\"%ls\" pid=%lu",
             cls, title[0] ? title : L"(none)", pid);
    found(L"%ls", line);
    if (ctx->kill) {
        PostMessageW(hwnd, WM_CLOSE, 0, 0);   // ask it to close (does not kill the process)
        done(L"WM_CLOSE sent to overlay window");
        ++g_fixed;
    }
    return TRUE;
}

static void scanOverlays(bool kill) {
    head(L"Full-screen lock overlays");
    if (!kill) info(L"(run with --kill-overlays to close suspicious overlay windows)");
    OverlayCtx ctx{kill && g_fix};
    EnumWindows(enumOverlays, reinterpret_cast<LPARAM>(&ctx));
}

// ---------------------------------------------------------------------------
// dropped Code-Integrity / WDAC policy files
// ---------------------------------------------------------------------------
static bool fileExists(const std::wstring& p) {
    DWORD a = GetFileAttributesW(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static void backupAndRemove(const std::wstring& path, const std::wstring& backupDir) {
    CreateDirectoryW(backupDir.c_str(), nullptr);
    std::wstring name = path.substr(path.find_last_of(L"\\/") + 1);
    std::wstring dst = backupDir + L"\\" + name;
    CopyFileW(path.c_str(), dst.c_str(), FALSE);   // best-effort backup
    if (DeleteFileW(path.c_str())) {
        done(L"backed up and removed");
        ++g_fixed;
    } else {
        wprintf(L"      -> could NOT remove (err=%lu). It is likely being ENFORCED now.\n", GetLastError());
        wprintf(L"         A Microsoft-signed / boot-anchored WDAC policy must be cleared\n");
        wprintf(L"         OFFLINE: boot WinRE/WinPE and delete this file, then reboot.\n");
    }
}

static void scanCodeIntegrity(bool remove) {
    head(L"Dropped Code-Integrity / WDAC policy (blocks .exe launches)");
    wchar_t win[MAX_PATH]; GetWindowsDirectoryW(win, MAX_PATH);
    std::wstring ci = std::wstring(win) + L"\\System32\\CodeIntegrity";
    std::wstring backup = std::wstring(win) + L"\\Temp\\rescue_ci_backup";

    std::wstring legacy = ci + L"\\SiPolicy.p7b";
    if (fileExists(legacy)) {
        found(L"legacy policy present: %ls", legacy.c_str());
        if (g_fix && remove) backupAndRemove(legacy, backup);
    }
    // multiple-policy format: CiPolicies\Active\*.cip
    std::wstring active = ci + L"\\CiPolicies\\Active";
    WIN32_FIND_DATAW fd; std::wstring pat = active + L"\\*.cip";
    HANDLE hf = FindFirstFileW(pat.c_str(), &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            std::wstring f = active + L"\\" + fd.cFileName;
            found(L"active policy present: %ls", f.c_str());
            if (g_fix && remove) backupAndRemove(f, backup);
        } while (FindNextFileW(hf, &fd));
        FindClose(hf);
    }
    if (!remove)
        info(L"(run with --remove-ci-policy to back up & attempt removal; offline is more reliable)");
}

// ---------------------------------------------------------------------------
static void usage() {
    wprintf(
        L"Rescue - Lockdown Breaker\n"
        L"Undo the levers malware uses to lock you out of your own machine.\n\n"
        L"USAGE:  lockdown_breaker [options]\n\n"
        L"  (no options)         scan and REPORT only - changes nothing\n"
        L"  --fix                apply fixes: clear restriction policies, restore the\n"
        L"                       login shell, release BlockInput\n"
        L"  --kill-overlays      with --fix, close full-screen lock overlay windows\n"
        L"  --remove-ci-policy   with --fix, back up & attempt to remove a dropped\n"
        L"                       WDAC/Code-Integrity policy (offline is more reliable)\n"
        L"  -h, --help           this help\n\n"
        L"Start with a plain scan, review the findings, then re-run with --fix.\n");
}

int wmain(int argc, wchar_t** argv) {
    bool killOverlays = false, removeCi = false;
    for (int i = 1; i < argc; ++i) {
        if      (!_wcsicmp(argv[i], L"--fix"))              g_fix = true;
        else if (!_wcsicmp(argv[i], L"--kill-overlays"))    killOverlays = true;
        else if (!_wcsicmp(argv[i], L"--remove-ci-policy")) removeCi = true;
        else if (!_wcsicmp(argv[i], L"-h") || !_wcsicmp(argv[i], L"--help")) { usage(); return 0; }
        else { wprintf(L"unknown option: %ls\n\n", argv[i]); usage(); return 2; }
    }

    wprintf(L"=====================================================\n");
    wprintf(L"  Rescue - Lockdown Breaker      %ls\n", g_fix ? L"[FIX MODE]" : L"[scan only]");
    wprintf(L"=====================================================\n");
    if (!priv::IsElevated())
        wprintf(L"  WARNING: not elevated - some keys/files will be unreachable.\n");

    // Acquire the authority we need to touch HKLM policy keys and OS files.
    priv::EnableDebugPrivilege();
    bool sys = priv::ImpersonateSystem();
    wprintf(L"  SYSTEM context: %ls\n", sys ? L"acquired" : L"unavailable (running as current user)");

    scanAllUserHives();
    head(L"Machine-wide restriction policies");
    scanPolicySet(HKEY_LOCAL_MACHINE, L"", kMachinePolicies,
                  sizeof(kMachinePolicies) / sizeof(kMachinePolicies[0]));
    scanShellHijack();
    unfreezeInput();
    scanOverlays(killOverlays);
    scanCodeIntegrity(removeCi);

    priv::Revert();

    wprintf(L"\n-----------------------------------------------------\n");
    if (g_findings == 0) {
        wprintf(L"  No lockdown levers detected. System looks clear.\n");
    } else if (g_fix) {
        wprintf(L"  Findings: %d   Fixed: %d\n", g_findings, g_fixed);
        if (g_fixed < g_findings)
            wprintf(L"  Some items need OFFLINE removal (WinPE) or a reboot.\n");
        wprintf(L"  Reboot when done so the shell reloads cleanly.\n");
    } else {
        wprintf(L"  Findings: %d  (scan only - nothing changed)\n", g_findings);
        wprintf(L"  Re-run with --fix to clear them.\n");
    }
    wprintf(L"-----------------------------------------------------\n");
    return 0;
}
