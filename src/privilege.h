// privilege.h - minimal, self-contained privilege helpers for Rescue.
//
// Rescue runs on the *infected, live* system, so to undo lockdowns it needs
// more than plain Administrator: it enables SeDebugPrivilege, borrows a SYSTEM
// token (from winlogon.exe) for the current thread, and flips on every
// privilege the token carries. These are the same fully-documented Win32 token
// APIs used by ExecTI / NSudo - no exploits, and it still requires the user to
// approve the UAC prompt (the embedded manifest is requireAdministrator).
//
// Nothing here is malware-specific; it is only the authority needed to write
// HKLM policy keys and delete OS-protected files that malware hid behind.
#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>

namespace priv {

// Enable a single named privilege on a token (best-effort).
inline bool EnablePrivilege(HANDLE token, const wchar_t* name) {
    LUID luid;
    if (!LookupPrivilegeValueW(nullptr, name, &luid)) return false;
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), nullptr, nullptr);
    return GetLastError() == ERROR_SUCCESS;
}

// Enable SeDebugPrivilege on our own process token.
inline bool EnableDebugPrivilege() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token))
        return false;
    bool ok = EnablePrivilege(token, SE_DEBUG_NAME);
    CloseHandle(token);
    return ok;
}

// Flip *every* privilege present on a token to enabled (SYSTEM-grade set).
inline void EnableAllPrivileges(HANDLE token) {
    DWORD len = 0;
    GetTokenInformation(token, TokenPrivileges, nullptr, 0, &len);
    if (!len) return;
    std::vector<BYTE> buf(len);
    if (!GetTokenInformation(token, TokenPrivileges, buf.data(), len, &len))
        return;
    auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
    for (DWORD i = 0; i < tp->PrivilegeCount; ++i)
        tp->Privileges[i].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, tp, len, nullptr, nullptr);
}

// Find a process by (case-insensitive) image name; returns PID or 0.
inline DWORD FindProcess(const wchar_t* image) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, image) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Impersonate SYSTEM on the current thread by duplicating winlogon's token.
// Call priv::Revert() when done. Returns false if unavailable.
inline bool ImpersonateSystem() {
    DWORD pid = FindProcess(L"winlogon.exe");
    if (!pid) return false;
    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!proc) return false;
    HANDLE tok = nullptr, dup = nullptr;
    bool ok = false;
    if (OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &tok)) {
        if (DuplicateTokenEx(tok, TOKEN_IMPERSONATE | TOKEN_QUERY, nullptr,
                             SecurityImpersonation, TokenImpersonation, &dup)) {
            EnableAllPrivileges(dup);
            ok = SetThreadToken(nullptr, dup) != 0;
        }
    }
    if (dup) CloseHandle(dup);
    if (tok) CloseHandle(tok);
    CloseHandle(proc);
    return ok;
}

inline void Revert() { RevertToSelf(); }

// True if the current process is running elevated (high integrity / admin).
inline bool IsElevated() {
    HANDLE token = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) return false;
    TOKEN_ELEVATION el{}; DWORD sz = sizeof(el);
    bool ok = GetTokenInformation(token, TokenElevation, &el, sizeof(el), &sz) && el.TokenIsElevated;
    CloseHandle(token);
    return ok;
}

} // namespace priv
