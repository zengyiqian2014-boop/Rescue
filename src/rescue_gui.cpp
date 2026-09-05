// rescue_gui.cpp - Rescue: the one window a user actually touches.
//
// Every other file here is an engine. This is the PRODUCT: a single native Win32
// application that unifies them into a simple antivirus a normal person can use -
// big buttons, a clear "Protected / Not protected" status, and a live log. The
// user never runs a command; the GUI drives the engines (scanner, guard,
// lockdown_breaker, backup) that sit next to it, streaming their output into the
// window. Native Win32 so it is one dependency-free, statically linked .exe that
// cross-compiles with MinGW for x86_64 and ARM64, exactly like the engines.
#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <thread>
#include <shlobj.h>

// ------------------------------------------------------------- control ids ---
enum {
    ID_QUICKSCAN = 1001, ID_FULLSCAN, ID_UNLOCK, ID_BACKUP, ID_PROTECT,
    ID_QUARANTINE, ID_LOG, ID_STATUS, ID_TITLE
};
#define WM_APP_APPEND (WM_APP + 1)   // wParam = wchar_t* (heap), append to log
#define WM_APP_BUSY   (WM_APP + 2)   // wParam = 0/1, running state changed

static HWND gLog = nullptr, gStatus = nullptr, gTitle = nullptr;
static HWND gBtn[6] = {0};
static HANDLE gGuardProc = nullptr;      // background real-time guard, when on
static bool  gBusy = false;              // a foreground engine is running
static HFONT gFontUI = nullptr, gFontTitle = nullptr, gFontMono = nullptr;

// --------------------------------------------------------------- helpers ------
static std::wstring exeDir() {
    wchar_t buf[MAX_PATH * 2]; GetModuleFileNameW(nullptr, buf, MAX_PATH * 2);
    std::wstring p = buf; size_t s = p.find_last_of(L"\\/");
    return s == std::wstring::npos ? L"." : p.substr(0, s);
}

static void appendLog(HWND hwnd, const wchar_t* text) {
    // marshal onto the UI thread
    size_t n = wcslen(text);
    wchar_t* copy = (wchar_t*)malloc((n + 1) * sizeof(wchar_t));
    if (!copy) return;
    memcpy(copy, text, (n + 1) * sizeof(wchar_t));
    PostMessageW(hwnd, WM_APP_APPEND, (WPARAM)copy, 0);
}

// Append text to the log edit at the end (runs on the UI thread).
static void logAtEnd(const wchar_t* text) {
    int len = GetWindowTextLengthW(gLog);
    SendMessageW(gLog, EM_SETSEL, len, len);
    SendMessageW(gLog, EM_REPLACESEL, FALSE, (LPARAM)text);
}

// ---- run one engine, streaming its stdout/stderr into the log ---------------
struct RunCtx { HWND hwnd; std::wstring cmd; bool foreground; };

static void runReader(HWND hwnd, HANDLE rd) {
    char buf[4096];
    DWORD got = 0;
    while (ReadFile(rd, buf, sizeof(buf) - 1, &got, nullptr) && got) {
        buf[got] = 0;
        int wn = MultiByteToWideChar(CP_ACP, 0, buf, (int)got, nullptr, 0);
        std::wstring w(wn, 0);
        MultiByteToWideChar(CP_ACP, 0, buf, (int)got, w.data(), wn);
        appendLog(hwnd, w.c_str());
    }
    CloseHandle(rd);
}

// Launch an engine. If foreground, disable buttons until it exits and reader
// drains. Returns the process handle (caller may keep it, e.g. the guard).
static HANDLE launchEngine(HWND hwnd, const std::wstring& cmdline, bool foreground) {
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof(sa); sa.bInheritHandle = TRUE;
    HANDLE rd = nullptr, wr = nullptr;
    if (!CreatePipe(&rd, &wr, &sa, 0)) return nullptr;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOW si{}; si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr; si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    std::wstring cmd = cmdline;
    std::vector<wchar_t> mut(cmd.begin(), cmd.end()); mut.push_back(0);
    PROCESS_INFORMATION pi{};
    BOOL ok = CreateProcessW(nullptr, mut.data(), nullptr, nullptr, TRUE,
                             CREATE_NO_WINDOW, nullptr, exeDir().c_str(), &si, &pi);
    CloseHandle(wr);
    if (!ok) {
        CloseHandle(rd);
        appendLog(hwnd, L"\r\n[!] could not start the engine.\r\n");
        return nullptr;
    }
    CloseHandle(pi.hThread);

    if (foreground) {
        SendMessageW(hwnd, WM_APP_BUSY, 1, 0);
        std::thread([hwnd, rd, hp = pi.hProcess]{
            runReader(hwnd, rd);
            WaitForSingleObject(hp, INFINITE);
            CloseHandle(hp);
            SendMessageW(hwnd, WM_APP_BUSY, 0, 0);
            appendLog(hwnd, L"\r\n---- done ----\r\n");
        }).detach();
        return nullptr;
    } else {
        // background (the guard): stream its output but keep the handle to stop it
        std::thread([hwnd, rd]{ runReader(hwnd, rd); }).detach();
        return pi.hProcess;
    }
}

static std::wstring tool(const wchar_t* name) {
    return L"\"" + exeDir() + L"\\" + name + L"\"";
}

// -------------------------------------------------------------- actions -------
static void setProtection(HWND hwnd, bool on) {
    if (on && !gGuardProc) {
        appendLog(hwnd, L"\r\n=== Real-time protection ON ===\r\n");
        gGuardProc = launchEngine(hwnd, tool(L"ransom_guard.exe") + L" --shield", false);
        if (!gGuardProc) appendLog(hwnd, L"[!] protection failed to start.\r\n");
    } else if (!on && gGuardProc) {
        TerminateProcess(gGuardProc, 0);
        CloseHandle(gGuardProc); gGuardProc = nullptr;
        appendLog(hwnd, L"\r\n=== Real-time protection OFF ===\r\n");
    }
    bool prot = gGuardProc != nullptr;
    SetWindowTextW(gStatus, prot ? L"  \u2714  Protected  -  real-time guard is running"
                                 : L"  \u26A0  Not protected  -  turn on real-time protection");
    SetWindowTextW(gBtn[4], prot ? L"Turn Protection OFF" : L"Turn Protection ON");
    InvalidateRect(gStatus, nullptr, TRUE);
}

static void onCommand(HWND hwnd, int id) {
    if (gBusy && id != ID_PROTECT && id != ID_QUARANTINE) {
        appendLog(hwnd, L"\r\n[busy - let the current task finish]\r\n");
        return;
    }
    switch (id) {
        case ID_QUICKSCAN:
            appendLog(hwnd, L"\r\n=== Quick scan ===\r\n");
            launchEngine(hwnd, tool(L"scanner.exe"), true); break;
        case ID_FULLSCAN:
            appendLog(hwnd, L"\r\n=== Full scan (all drives) ===\r\n");
            launchEngine(hwnd, tool(L"scanner.exe") + L" --full", true); break;
        case ID_UNLOCK:
            appendLog(hwnd, L"\r\n=== Unlock / clean lockdown ===\r\n");
            launchEngine(hwnd, tool(L"lockdown_breaker.exe") + L" --fix --kill-overlays --kill-effects", true);
            break;
        case ID_BACKUP: {
            // Let the user pick a backup disk/folder (external drive recommended).
            BROWSEINFOW bi{}; bi.hwndOwner = hwnd;
            bi.lpszTitle = L"Choose a BACKUP DISK or folder (an external drive is best)";
            bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
            LPITEMIDLIST pidl = SHBrowseForFolderW(&bi);
            if (pidl) {
                wchar_t path[MAX_PATH];
                if (SHGetPathFromIDListW(pidl, path)) {
                    appendLog(hwnd, L"\r\n=== Backup ===\r\n");
                    launchEngine(hwnd, tool(L"backup.exe") + L" --snapshot \"" + path + L"\" --keep 10", true);
                }
                CoTaskMemFree(pidl);
            }
            break;
        }
        case ID_PROTECT:
            setProtection(hwnd, gGuardProc == nullptr); break;
        case ID_QUARANTINE: {
            wchar_t pd[MAX_PATH * 2]; DWORD n = GetEnvironmentVariableW(L"ProgramData", pd, MAX_PATH * 2);
            std::wstring q = (n ? std::wstring(pd) : L"C:\\ProgramData") + L"\\Rescue\\Quarantine";
            CreateDirectoryW((std::wstring(n ? pd : L"C:\\ProgramData") + L"\\Rescue").c_str(), nullptr);
            CreateDirectoryW(q.c_str(), nullptr);
            ShellExecuteW(hwnd, L"explore", q.c_str(), nullptr, nullptr, SW_SHOW);
            break;
        }
    }
}

// --------------------------------------------------------------- layout -------
static HWND mkButton(HWND parent, int id, const wchar_t* text, int x, int y, int w, int h) {
    HWND b = CreateWindowExW(0, L"BUTTON", text,
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, y, w, h, parent, (HMENU)(INT_PTR)id,
        (HINSTANCE)GetWindowLongPtrW(parent, GWLP_HINSTANCE), nullptr);
    SendMessageW(b, WM_SETFONT, (WPARAM)gFontUI, TRUE);
    return b;
}

static void layout(HWND hwnd) {
    RECT rc; GetClientRect(hwnd, &rc);
    int W = rc.right, pad = 16;
    int titleH = 40, statusH = 40;
    MoveWindow(gTitle, 0, 0, W, titleH, TRUE);
    MoveWindow(gStatus, 0, titleH, W, statusH, TRUE);
    int by = titleH + statusH + pad;
    int bw = (W - pad * 4) / 3, bh = 52;
    const int order[6] = {ID_QUICKSCAN, ID_FULLSCAN, ID_PROTECT, ID_UNLOCK, ID_BACKUP, ID_QUARANTINE};
    for (int i = 0; i < 6; ++i) {
        HWND b = GetDlgItem(hwnd, order[i]);
        int col = i % 3, row = i / 3;
        MoveWindow(b, pad + col * (bw + pad), by + row * (bh + pad), bw, bh, TRUE);
    }
    int logY = by + 2 * (bh + pad) + pad;
    MoveWindow(gLog, pad, logY, W - pad * 2, rc.bottom - logY - pad, TRUE);
}

// --------------------------------------------------------------- wndproc ------
static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_CREATE: {
        HINSTANCE hi = ((LPCREATESTRUCTW)lp)->hInstance;
        gFontTitle = CreateFontW(30, 0,0,0, FW_SEMIBOLD, 0,0,0, DEFAULT_CHARSET,0,0,0,0, L"Segoe UI");
        gFontUI    = CreateFontW(19, 0,0,0, FW_NORMAL,   0,0,0, DEFAULT_CHARSET,0,0,0,0, L"Segoe UI");
        gFontMono  = CreateFontW(15, 0,0,0, FW_NORMAL,   0,0,0, DEFAULT_CHARSET,0,0,0,0, L"Consolas");

        gTitle = CreateWindowExW(0, L"STATIC", L"  Rescue  \u2014  Anti-Ransomware Protection",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE, 0,0,0,0, hwnd,
            (HMENU)(INT_PTR)ID_TITLE, hi, nullptr);
        SendMessageW(gTitle, WM_SETFONT, (WPARAM)gFontTitle, TRUE);

        gStatus = CreateWindowExW(0, L"STATIC", L"",
            WS_CHILD | WS_VISIBLE | SS_LEFTNOWORDWRAP | SS_CENTERIMAGE, 0,0,0,0, hwnd,
            (HMENU)(INT_PTR)ID_STATUS, hi, nullptr);
        SendMessageW(gStatus, WM_SETFONT, (WPARAM)gFontUI, TRUE);

        gBtn[0] = mkButton(hwnd, ID_QUICKSCAN,  L"Quick Scan",        0,0,0,0);
        gBtn[1] = mkButton(hwnd, ID_FULLSCAN,   L"Full Scan",         0,0,0,0);
        gBtn[4] = mkButton(hwnd, ID_PROTECT,    L"Turn Protection ON",0,0,0,0);
        gBtn[2] = mkButton(hwnd, ID_UNLOCK,     L"Unlock / Clean",    0,0,0,0);
        gBtn[3] = mkButton(hwnd, ID_BACKUP,     L"Back Up My Files",  0,0,0,0);
        gBtn[5] = mkButton(hwnd, ID_QUARANTINE, L"Quarantine",        0,0,0,0);

        gLog = CreateWindowExW(WS_EX_CLIENTEDGE, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL,
            0,0,0,0, hwnd, (HMENU)(INT_PTR)ID_LOG, hi, nullptr);
        SendMessageW(gLog, WM_SETFONT, (WPARAM)gFontMono, TRUE);

        setProtection(hwnd, false);
        logAtEnd(L"Rescue ready. Click Quick Scan to check this PC, or Turn Protection ON\r\n"
                 L"for real-time anti-ransomware defense. Everything runs with your approval.\r\n");
        layout(hwnd);
        return 0;
    }
    case WM_SIZE: layout(hwnd); return 0;

    case WM_CTLCOLORSTATIC: {
        HWND ctl = (HWND)lp; HDC dc = (HDC)wp;
        if (ctl == gTitle) {
            SetTextColor(dc, RGB(255,255,255)); SetBkColor(dc, RGB(20,40,80));
            static HBRUSH b = CreateSolidBrush(RGB(20,40,80)); return (LRESULT)b;
        }
        if (ctl == gStatus) {
            bool prot = gGuardProc != nullptr;
            COLORREF bg = prot ? RGB(20,120,50) : RGB(150,60,20);
            SetTextColor(dc, RGB(255,255,255)); SetBkColor(dc, bg);
            static HBRUSH gb = CreateSolidBrush(RGB(20,120,50));
            static HBRUSH rb = CreateSolidBrush(RGB(150,60,20));
            return (LRESULT)(prot ? gb : rb);
        }
        break;
    }
    case WM_COMMAND:
        if (HIWORD(wp) == BN_CLICKED) onCommand(hwnd, LOWORD(wp));
        return 0;

    case WM_APP_APPEND: {
        wchar_t* text = (wchar_t*)wp;
        if (text) { logAtEnd(text); free(text); }
        return 0;
    }
    case WM_APP_BUSY: {
        gBusy = wp != 0;
        for (int i = 0; i < 6; ++i) {
            int id = GetDlgCtrlID(gBtn[i]);
            if (id == ID_PROTECT || id == ID_QUARANTINE) continue;
            EnableWindow(gBtn[i], !gBusy);
        }
        return 0;
    }
    case WM_CLOSE:
        if (gGuardProc) { TerminateProcess(gGuardProc, 0); CloseHandle(gGuardProc); gGuardProc = nullptr; }
        DestroyWindow(hwnd); return 0;
    case WM_DESTROY: PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, wp, lp);
}

int WINAPI wWinMain(HINSTANCE hInst, HINSTANCE, PWSTR, int nShow) {
    CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    INITCOMMONCONTROLSEX icc{ sizeof(icc), ICC_STANDARD_CLASSES }; InitCommonControlsEx(&icc);

    WNDCLASSW wc{};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInst;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.lpszClassName = L"RescueMainWindow";
    wc.hIcon = LoadIconW(nullptr, IDI_SHIELD);
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, wc.lpszClassName, L"Rescue",
        WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 780, 620,
        nullptr, nullptr, hInst, nullptr);
    ShowWindow(hwnd, nShow);
    UpdateWindow(hwnd);

    MSG msg;
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    return 0;
}
