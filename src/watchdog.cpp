// watchdog.cpp - Rescue module 5: keep the guard alive, and keep each other
// alive.
//
// A protection tool that a malicious process can simply kill is no protection.
// This is a Windows service ("RescueWatchdog") that (1) makes sure Ransom Guard
// is always running, and (2) runs a paired companion process that watches the
// service while the service watches the companion - kill either one and the
// other brings it back.
//
// HONEST CEILING: two cooperating user-mode processes raise the bar (an attacker
// must kill both within the same instant, repeatedly), but a sufficiently
// privileged attacker can still win the race. Truly un-killable protection needs
// a Protected-Process-Light service or the kernel minifilter (Phase 6). This is
// the best that documented user-mode APIs allow, and it says so.
//
//   watchdog --install       install + start the service (run elevated)
//   watchdog --uninstall     stop + remove the service
//   watchdog --status        show service + guard state
//   watchdog --run-service   (invoked by the SCM; not for manual use)
//   watchdog --peer          (companion mode; spawned by the service)
#include <windows.h>
#include <winsvc.h>
#include <cstdio>
#include <string>
#include "privilege.h"

static const wchar_t* SVC_NAME = L"RescueWatchdog";
static const wchar_t* SVC_DISP = L"Rescue Watchdog";
static const wchar_t* GUARD_EXE = L"ransom_guard.exe";
static const wchar_t* GUARD_ARGS = L"--watch C:\\Users";   // service runs as SYSTEM: watch all profiles

static SERVICE_STATUS        g_status{};
static SERVICE_STATUS_HANDLE g_statusHandle = nullptr;
static HANDLE                g_stopEvent = nullptr;

// --- path helpers -----------------------------------------------------------
static std::wstring selfPath() {
    wchar_t p[MAX_PATH]; GetModuleFileNameW(nullptr, p, MAX_PATH); return p;
}
static std::wstring selfDir() {
    std::wstring p = selfPath(); size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? L"." : p.substr(0, s);
}

// --- launch a detached process ---------------------------------------------
static bool launch(const std::wstring& cmdline) {
    std::wstring mutable_cmd = cmdline;
    STARTUPINFOW si{}; si.cb = sizeof si; si.dwFlags = STARTF_USESHOWWINDOW; si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!CreateProcessW(nullptr, mutable_cmd.data(), nullptr, nullptr, FALSE,
                        CREATE_NO_WINDOW, nullptr, selfDir().c_str(), &si, &pi))
        return false;
    CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
    return true;
}

// --- SCM state helpers ------------------------------------------------------
static DWORD queryServiceState() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return 0;
    DWORD state = 0;
    SC_HANDLE s = OpenServiceW(scm, SVC_NAME, SERVICE_QUERY_STATUS);
    if (s) {
        SERVICE_STATUS st{};
        if (QueryServiceStatus(s, &st)) state = st.dwCurrentState;
        CloseServiceHandle(s);
    }
    CloseServiceHandle(scm);
    return state;
}
static bool startServiceByName() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return false;
    bool ok = false;
    SC_HANDLE s = OpenServiceW(scm, SVC_NAME, SERVICE_START);
    if (s) { ok = StartServiceW(s, 0, nullptr) != 0; CloseServiceHandle(s); }
    CloseServiceHandle(scm);
    return ok;
}

// --- ensure the guard is running -------------------------------------------
static void ensureGuard() {
    if (priv::FindProcess(GUARD_EXE)) return;
    std::wstring cmd = L"\"" + selfDir() + L"\\" + GUARD_EXE + L"\" " + GUARD_ARGS;
    launch(cmd);
}

// --- companion (peer) mode --------------------------------------------------
// Watches the service; if it is not RUNNING, (re)starts it. Runs until killed;
// when it is killed the service's own loop respawns it.
static int runPeer() {
    for (;;) {
        DWORD st = queryServiceState();
        if (st != SERVICE_RUNNING && st != SERVICE_START_PENDING)
            startServiceByName();
        Sleep(3000);
    }
}
static void ensurePeer() {
    // one peer at a time
    static bool spawnedOnce = false;
    // crude presence check: look for a second copy of ourselves in --peer mode.
    // Simplest robust approach: always try to keep exactly one peer by tracking
    // a named mutex the peer holds.
    HANDLE m = OpenMutexW(SYNCHRONIZE, FALSE, L"Global\\RescueWatchdogPeer");
    if (m) { CloseHandle(m); return; }      // peer alive (holds the mutex)
    std::wstring cmd = L"\"" + selfPath() + L"\" --peer";
    launch(cmd);
    spawnedOnce = true;
    (void)spawnedOnce;
}

// --- service plumbing -------------------------------------------------------
static void reportStatus(DWORD state, DWORD wait = 0) {
    static DWORD checkpoint = 1;
    g_status.dwCurrentState = state;
    g_status.dwWin32ExitCode = NO_ERROR;
    g_status.dwWaitHint = wait;
    g_status.dwControlsAccepted = (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    g_status.dwCheckPoint = (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0 : checkpoint++;
    SetServiceStatus(g_statusHandle, &g_status);
}

static DWORD WINAPI ctrlHandler(DWORD ctrl, DWORD, LPVOID, LPVOID) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        reportStatus(SERVICE_STOP_PENDING);
        if (g_stopEvent) SetEvent(g_stopEvent);
        return NO_ERROR;
    }
    if (ctrl == SERVICE_CONTROL_INTERROGATE) { SetServiceStatus(g_statusHandle, &g_status); return NO_ERROR; }
    return ERROR_CALL_NOT_IMPLEMENTED;
}

static void WINAPI serviceMain(DWORD, LPWSTR*) {
    g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    g_statusHandle = RegisterServiceCtrlHandlerExW(SVC_NAME, ctrlHandler, nullptr);
    if (!g_statusHandle) return;
    reportStatus(SERVICE_START_PENDING, 3000);
    g_stopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    reportStatus(SERVICE_RUNNING);

    // main protection loop
    while (WaitForSingleObject(g_stopEvent, 4000) == WAIT_TIMEOUT) {
        ensureGuard();
        ensurePeer();
    }
    reportStatus(SERVICE_STOPPED);
}

// --- install / uninstall ----------------------------------------------------
static int installService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE);
    if (!scm) { wprintf(L"OpenSCManager failed (%lu) - run elevated.\n", GetLastError()); return 1; }
    std::wstring bin = L"\"" + selfPath() + L"\" --run-service";
    SC_HANDLE s = CreateServiceW(scm, SVC_NAME, SVC_DISP, SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
        bin.c_str(), nullptr, nullptr, nullptr, nullptr, nullptr);
    if (!s) {
        DWORD e = GetLastError();
        if (e == ERROR_SERVICE_EXISTS) wprintf(L"Service already installed.\n");
        else wprintf(L"CreateService failed (%lu)\n", e);
        CloseServiceHandle(scm); return e == ERROR_SERVICE_EXISTS ? 0 : 1;
    }
    // auto-restart on crash
    SERVICE_FAILURE_ACTIONS fa{}; SC_ACTION acts[3];
    acts[0] = {SC_ACTION_RESTART, 5000}; acts[1] = {SC_ACTION_RESTART, 5000}; acts[2] = {SC_ACTION_RESTART, 5000};
    fa.dwResetPeriod = 86400; fa.cActions = 3; fa.lpsaActions = acts;
    ChangeServiceConfig2W(s, SERVICE_CONFIG_FAILURE_ACTIONS, &fa);
    StartServiceW(s, 0, nullptr);
    wprintf(L"Installed and started '%ls'. It keeps %ls running and self-heals.\n", SVC_NAME, GUARD_EXE);
    CloseServiceHandle(s); CloseServiceHandle(scm);
    return 0;
}

static int uninstallService() {
    SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) { wprintf(L"OpenSCManager failed - run elevated.\n"); return 1; }
    SC_HANDLE s = OpenServiceW(scm, SVC_NAME, SERVICE_STOP | DELETE);
    if (!s) { wprintf(L"Service not installed.\n"); CloseServiceHandle(scm); return 0; }
    SERVICE_STATUS st{}; ControlService(s, SERVICE_CONTROL_STOP, &st);
    if (DeleteService(s)) wprintf(L"Removed '%ls'.\n", SVC_NAME);
    else wprintf(L"DeleteService failed (%lu)\n", GetLastError());
    CloseServiceHandle(s); CloseServiceHandle(scm);
    return 0;
}

static int status() {
    DWORD st = queryServiceState();
    const wchar_t* s = st == SERVICE_RUNNING ? L"RUNNING" :
                       st == SERVICE_STOPPED ? L"STOPPED" :
                       st == 0 ? L"NOT INSTALLED" : L"transitioning";
    wprintf(L"Service '%ls': %ls\n", SVC_NAME, s);
    wprintf(L"Guard '%ls': %ls\n", GUARD_EXE, priv::FindProcess(GUARD_EXE) ? L"running" : L"not running");
    return 0;
}

int wmain(int argc, wchar_t** argv) {
    if (argc >= 2) {
        if (!_wcsicmp(argv[1], L"--install"))     return installService();
        if (!_wcsicmp(argv[1], L"--uninstall"))   return uninstallService();
        if (!_wcsicmp(argv[1], L"--status"))      return status();
        if (!_wcsicmp(argv[1], L"--peer")) {
            HANDLE m = CreateMutexW(nullptr, TRUE, L"Global\\RescueWatchdogPeer");
            if (GetLastError() == ERROR_ALREADY_EXISTS) return 0;   // a peer already runs
            int r = runPeer();
            if (m) CloseHandle(m);
            return r;
        }
        if (!_wcsicmp(argv[1], L"--run-service")) {
            SERVICE_TABLE_ENTRYW table[] = { { (LPWSTR)SVC_NAME, serviceMain }, { nullptr, nullptr } };
            if (!StartServiceCtrlDispatcherW(table)) {
                wprintf(L"This mode is for the Service Control Manager. Use --install.\n");
                return 1;
            }
            return 0;
        }
    }
    wprintf(
        L"Rescue - Watchdog\n"
        L"Keeps Ransom Guard alive and self-heals via a paired companion process.\n\n"
        L"  watchdog --install     install + start the service (run elevated)\n"
        L"  watchdog --uninstall   stop + remove the service\n"
        L"  watchdog --status      show service + guard state\n\n"
        L"Note: two cooperating user-mode processes raise the bar but are not\n"
        L"un-killable. Tamper-proof protection needs the kernel filter (Phase 6).\n");
    return 0;
}
