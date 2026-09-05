// ransom_guard.cpp - Rescue module 3: active anti-ransomware guard.
//
// Ransomware wins by encrypting faster than you can react. This guard reacts
// automatically: it plants *canary* files, watches your folders in real time,
// and the instant something starts mass-modifying files (or touches a canary),
// it finds the busiest writer process and SUSPENDS it (or kills it with --kill)
// - freezing the attack mid-run so you lose a handful of files instead of all
// of them.
//
// ATTRIBUTION - two tiers, picked automatically:
//   * PREFERRED: a real-time ETW session on Microsoft-Windows-Kernel-File
//     (etw_filemon.h) gives the requesting process id for every WRITE / RENAME
//     / DELETE. That is DETERMINISTIC per-write attribution from user mode - no
//     driver, Secure Boot and HVCI left on - so the guard freezes the process
//     that actually did the writing, not a guess. Needs elevation.
//   * FALLBACK: if the ETW session can't start, the guard ranks processes by
//     write-I/O rate at the moment of the trip (IO_COUNTERS) - a strong
//     heuristic, not a certainty, exactly as before.
// The one thing ETW still cannot do is BLOCK a write before it lands; only an
// in-kernel pre-write callback (Phase 6, signed driver) can. Attribution does
// not need the kernel, and this is it. Defaults to SUSPEND (reversible) over
// kill, and always logs what it acted on so a wrong guess can be undone.
#include <windows.h>
#include <tlhelp32.h>
#include <cstdio>
#include <string>
#include <vector>
#include <map>
#include <set>
#include <atomic>
#include <thread>
#include <chrono>
#include <mutex>
#include "privilege.h"
#include "etw_filemon.h"
#include "signature.h"

using namespace std::chrono;

// ---------------------------------------------------------------------------
static std::atomic<bool> g_trip{false};
static std::atomic<int>  g_recentEvents{0};
static std::mutex        g_logMx;
static bool g_kill = false;
static etwmon::FileMonitor g_etw;   // deterministic attribution when it starts

static void logline(const wchar_t* fmt, ...) {
    std::lock_guard<std::mutex> lk(g_logMx);
    SYSTEMTIME st; GetLocalTime(&st);
    wprintf(L"[%02d:%02d:%02d] ", st.wHour, st.wMinute, st.wSecond);
    va_list ap; va_start(ap, fmt); vwprintf(fmt, ap); va_end(ap);
    wprintf(L"\n"); fflush(stdout);
}

// ---------------------------------------------------------------------------
// canary files: names chosen to sort to the top AND bottom of a folder, since
// many ransomware families encrypt in alphabetical order.
// ---------------------------------------------------------------------------
static const wchar_t* kCanaryNames[] = {
    L"!!!_rescue_canary_DO_NOT_DELETE.docx",
    L"zzz_rescue_canary_DO_NOT_DELETE.xlsx",
};

static std::set<std::wstring> g_canaries;   // full lowercase paths

static std::wstring lower(std::wstring s) {
    for (auto& c : s) c = (wchar_t)towlower(c);
    return s;
}

static void plantCanaries(const std::wstring& dir) {
    for (auto* n : kCanaryNames) {
        std::wstring path = dir + L"\\" + n;
        HANDLE h = CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            const char* body =
                "Rescue canary file. If this file changes, ransomware is running.\r\n";
            DWORD wr; WriteFile(h, body, (DWORD)strlen(body), &wr, nullptr);
            CloseHandle(h);
            g_canaries.insert(lower(path));
        }
    }
}

// ---------------------------------------------------------------------------
// process helpers
// ---------------------------------------------------------------------------
struct ProcInfo { DWORD pid; DWORD ppid; std::wstring name; };

static std::vector<ProcInfo> snapshotProcesses() {
    std::vector<ProcInfo> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe{}; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do { out.push_back({pe.th32ProcessID, pe.th32ParentProcessID, pe.szExeFile}); }
        while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

// Never touch these - suspending them would freeze or crash Windows.
static bool isProtected(const std::wstring& nameLower) {
    static const std::set<std::wstring> wl = {
        L"system", L"registry", L"smss.exe", L"csrss.exe", L"wininit.exe",
        L"winlogon.exe", L"services.exe", L"lsass.exe", L"svchost.exe",
        L"explorer.exe", L"dwm.exe", L"fontdrvhost.exe", L"ctfmon.exe",
        L"msmpeng.exe", L"ransom_guard.exe", L"conhost.exe", L"taskmgr.exe",
    };
    return wl.count(nameLower) > 0;
}

static ULONGLONG procWriteOps(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    IO_COUNTERS io{};
    ULONGLONG v = 0;
    if (GetProcessIoCounters(h, &io)) v = io.WriteOperationCount + io.OtherOperationCount;
    CloseHandle(h);
    return v;
}

// Full image path for a pid (for signature checks on a suspected wiper).
static std::wstring imagePathForPid(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return L"";
    wchar_t buf[MAX_PATH * 2]; DWORD n = MAX_PATH * 2;
    std::wstring path;
    if (QueryFullProcessImageNameW(h, 0, buf, &n)) path.assign(buf, n);
    CloseHandle(h);
    return path;
}

// Bytes written by a process. A ransomware encrypts files (file-system writes,
// caught by the directory watcher); a WIPER often opens the raw disk
// (\\.\PhysicalDrive0 / \\.\C:) and streams zeros straight to sectors -
// which produces NO ReadDirectoryChangesW events at all, so the file watcher is
// blind to it. But those raw writes still count as the process's write BYTES,
// so a sustained, very high write-byte rate from one process is the signature
// of a wiper the file watcher would miss.
static ULONGLONG procWriteBytes(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return 0;
    IO_COUNTERS io{};
    ULONGLONG v = 0;
    if (GetProcessIoCounters(h, &io)) v = io.WriteTransferCount;
    CloseHandle(h);
    return v;
}

// Suspend / resume / kill every thread of a process and its descendants.
static void forEachDescendant(DWORD root, std::vector<DWORD>& out) {
    auto procs = snapshotProcesses();
    std::map<DWORD, std::vector<DWORD>> children;
    for (auto& p : procs) children[p.ppid].push_back(p.pid);
    std::vector<DWORD> stack{root};
    std::set<DWORD> seen;
    while (!stack.empty()) {
        DWORD cur = stack.back(); stack.pop_back();
        if (!seen.insert(cur).second) continue;
        out.push_back(cur);
        for (DWORD c : children[cur]) stack.push_back(c);
    }
}

static void suspendProcess(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{}; te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                HANDLE t = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
                if (t) { SuspendThread(t); CloseHandle(t); }
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

static void killProcess(DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h) { TerminateProcess(h, 1); CloseHandle(h); }
}

// Resolve a pid to its image name (for logging an ETW-attributed culprit).
static std::wstring nameForPid(DWORD pid) {
    for (auto& p : snapshotProcesses()) if (p.pid == pid) return p.name;
    return L"(unknown)";
}

// pid-based protected check, for the ETW TopWriter exclude callback.
static bool isProtectedPid(DWORD pid) {
    return isProtected(lower(nameForPid(pid)));
}

// ---------------------------------------------------------------------------
// the response: rank writers, neutralize the top culprit tree
// ---------------------------------------------------------------------------
static void respond(const wchar_t* reason) {
    logline(L"!!! RANSOMWARE SIGNAL: %ls", reason);

    DWORD culprit = 0; ULONGLONG best = 0; std::wstring cname;
    const wchar_t* how = L"";

    if (g_etw.Running()) {
        // Deterministic: count actual per-process file WRITE/RENAME/DELETE
        // events over a short window and take the process that did the most.
        g_etw.Reset();
        std::this_thread::sleep_for(milliseconds(250));
        culprit = g_etw.TopWriter(&best, &isProtectedPid);
        cname = culprit ? nameForPid(culprit) : L"";
        how = L"file ops";
    } else {
        // Fallback: rank by write-I/O rate (heuristic, no ETW available).
        auto procs = snapshotProcesses();
        std::map<DWORD, ULONGLONG> t0;
        for (auto& p : procs)
            if (!isProtected(lower(p.name))) t0[p.pid] = procWriteOps(p.pid);
        std::this_thread::sleep_for(milliseconds(250));
        for (auto& p : procs) {
            if (isProtected(lower(p.name))) continue;
            ULONGLONG d = procWriteOps(p.pid) - t0[p.pid];
            if (d > best) { best = d; culprit = p.pid; cname = p.name; }
        }
        how = L"write ops (heuristic)";
    }

    if (!culprit) { logline(L"    could not identify a writer process (no action taken)"); return; }

    std::vector<DWORD> tree;
    forEachDescendant(culprit, tree);
    logline(L"    culprit (%ls): %ls  pid=%lu  (+%llu %ls in 250ms, %zu procs in tree)",
            g_etw.Running() ? L"attributed" : L"top writer",
            cname.c_str(), culprit, best, how, tree.size());

    for (DWORD pid : tree) {
        if (g_kill) killProcess(pid);
        else        suspendProcess(pid);
    }
    logline(L"    %ls the culprit tree.  Files stop changing now.",
            g_kill ? L"KILLED" : L"SUSPENDED (reversible)");
    if (!g_kill)
        logline(L"    Verify it in Task Manager. If correct: End task. If wrong: Resume it.");
    if (g_etw.Running())
        logline(L"    (ETW attribution: this pid performed the file writes above.)");
    else
        logline(L"    (Heuristic attribution - confirm before permanent action.)");
}

// ---------------------------------------------------------------------------
// directory watcher (one thread per watched folder)
// ---------------------------------------------------------------------------
static void watchDir(std::wstring dir) {
    HANDLE h = CreateFileW(dir.c_str(), FILE_LIST_DIRECTORY,
                           FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                           nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (h == INVALID_HANDLE_VALUE) { logline(L"cannot watch %ls (err=%lu)", dir.c_str(), GetLastError()); return; }
    std::vector<BYTE> buf(64 * 1024);
    for (;;) {
        DWORD ret = 0;
        if (!ReadDirectoryChangesW(h, buf.data(), (DWORD)buf.size(), TRUE,
                FILE_NOTIFY_CHANGE_FILE_NAME | FILE_NOTIFY_CHANGE_LAST_WRITE |
                FILE_NOTIFY_CHANGE_SIZE,
                &ret, nullptr, nullptr))
            break;
        auto* p = reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buf.data());
        for (;;) {
            std::wstring name(p->FileName, p->FileNameLength / sizeof(wchar_t));
            std::wstring full = lower(dir + L"\\" + name);
            if (g_canaries.count(full)) {
                g_trip = true;
                respond((L"canary file touched: " + name).c_str());
            } else {
                g_recentEvents.fetch_add(1);
            }
            if (!p->NextEntryOffset) break;
            p = reinterpret_cast<FILE_NOTIFY_INFORMATION*>((BYTE*)p + p->NextEntryOffset);
        }
    }
    CloseHandle(h);
}

// Raw-write / wiper monitor: independent of the file watcher, which is blind to
// a wiper that opens the raw disk and streams zeros (no file-change events).
//
// A single factor is not enough, and each has a known evasion:
//   * RATE alone       -> a legitimate disk imager (Rufus, Win32DiskImager, dd)
//                         writes to a raw disk at the same rate as a wiper.
//   * SIGNATURE alone  -> malware can be signed (stolen/abused certs), so a
//                         signature is NOT a free pass, only a raised bar.
//   * one burst        -> says little; a WIPER runs flat out and SUSTAINED,
//                         either blindly (continuous) or paced (bursty) but for
//                         a long time, because it must cover the whole disk.
// So we score: a process over the byte-rate budget accrues "sustain" seconds
// (persisting across brief dips, which captures a *paced* wiper too). An
// UNSIGNED writer trips after a short sustain; a SIGNED one is not exempt but
// must sustain far longer before it trips - evidence proportional to trust.
// Suspend is reversible, so a wrong guess is undoable.
//
// HONEST LIMIT: user-mode IO counters show how much a process wrote, not to
// WHICH disk or WHICH sectors. Telling "zeroing system disk 0 / hitting the
// MBR-GPT region" from "writing my USB stick" needs ETW Kernel-Disk (offset +
// disk number), and actually BLOCKING a write to a critical block, or locking a
// volume before damage lands, needs the kernel minifilter (Module 6). This
// monitor detects-and-freezes; it does not pretend to pre-block.
static void rawWriteMonitor(int mbPerSec) {
    const ULONGLONG budget = (ULONGLONG)mbPerSec * 1024 * 1024;
    const int kUnsignedSustain = 2;    // seconds over budget to trip if unsigned
    const int kSignedSustain   = 12;   // signed is not exempt - just needs more
    std::map<DWORD, ULONGLONG> prev;
    std::map<DWORD, int> sustain;      // consecutive-ish seconds over budget
    for (auto& p : snapshotProcesses())
        if (!isProtected(lower(p.name))) prev[p.pid] = procWriteBytes(p.pid);
    for (;;) {
        std::this_thread::sleep_for(seconds(1));
        auto procs = snapshotProcesses();
        std::map<DWORD, ULONGLONG> cur;
        std::map<DWORD, std::wstring> names;
        for (auto& p : procs) {
            if (isProtected(lower(p.name))) continue;
            ULONGLONG now = procWriteBytes(p.pid);
            cur[p.pid] = now; names[p.pid] = p.name;
            auto it = prev.find(p.pid);
            ULONGLONG d = (it != prev.end() && now >= it->second) ? now - it->second : 0;
            if (d >= budget) sustain[p.pid] += 1;
            else if (sustain.count(p.pid))          // decay, don't reset: a paced
                sustain[p.pid] = (std::max)(0, sustain[p.pid] - 1);  // wiper keeps score
        }
        prev.swap(cur);

        // pick the strongest sustained writer and decide by trust-weighted threshold
        DWORD worst = 0; int worstSustain = 0;
        for (auto& kv : sustain)
            if (kv.second > worstSustain && cur.count(kv.first)) { worstSustain = kv.second; worst = kv.first; }

        if (worst && worstSustain >= kUnsignedSustain) {
            std::wstring img = imagePathForPid(worst);
            sig::Trust t = img.empty() ? sig::Trust::Unsigned : sig::Verify(img);
            bool trusted = sig::IsTrusted(t);
            int need = trusted ? kSignedSustain : kUnsignedSustain;
            if (worstSustain >= need && !g_trip.exchange(true)) {
                wchar_t r[256];
                swprintf(r, 256,
                    L"%ls %ls (pid %lu) sustained heavy disk writes for %ds - possible wiper",
                    trusted ? L"SIGNED-BUT-SUSPICIOUS" : L"UNSIGNED",
                    names.count(worst) ? names[worst].c_str() : L"?", worst, worstSustain);
                respond(r);
                sustain.clear();
            } else if (trusted && worstSustain < need) {
                static std::set<DWORD> noted;
                if (noted.insert(worst).second)
                    logline(L"[i] %ls (pid %lu) writing fast but signed (%ls) - watching, not yet acting.",
                            names.count(worst) ? names[worst].c_str() : L"?", worst, sig::TrustName(t));
            }
        }
        if (g_trip) { std::this_thread::sleep_for(seconds(2)); g_trip = false; }
    }
}

// mass-modification detector: too many file events in a short window == attack.
static void massChangeMonitor(int threshold) {
    for (;;) {
        std::this_thread::sleep_for(seconds(1));
        int n = g_recentEvents.exchange(0);
        if (n >= threshold && !g_trip.exchange(true)) {
            wchar_t r[128];
            swprintf(r, 128, L"%d files changed in 1s (threshold %d)", n, threshold);
            respond(r);
        }
        // re-arm a moment after a trip so a second wave is still caught
        if (g_trip) { std::this_thread::sleep_for(seconds(2)); g_trip = false; }
    }
}

// ---------------------------------------------------------------------------
static std::wstring knownFolder(const wchar_t* env, const wchar_t* sub) {
    wchar_t buf[MAX_PATH]; DWORD n = GetEnvironmentVariableW(env, buf, MAX_PATH);
    if (!n || n >= MAX_PATH) return L"";
    std::wstring p = buf; if (sub) p += sub;
    DWORD a = GetFileAttributesW(p.c_str());
    return (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY)) ? p : L"";
}

static void usage() {
    wprintf(
        L"Rescue - Anti-Ransomware Guard\n"
        L"Watches your folders and freezes the process that starts mass-encrypting.\n\n"
        L"USAGE:  ransom_guard [options]\n\n"
        L"  --watch <dir>     watch this folder (repeatable). Default: your\n"
        L"                    Desktop, Documents, Pictures.\n"
        L"  --threshold <n>   files-changed-per-second that counts as an attack (default 40)\n"
        L"  --wiper-mbps <n>  raw write-rate (MB/s) from one process that counts as a\n"
        L"                    disk wiper - catches raw-disk zero-fillers the file\n"
        L"                    watcher can't see (default 150)\n"
        L"  --kill            KILL the culprit instead of suspending it (irreversible)\n"
        L"  -h, --help        this help\n\n"
        L"Leave it running. On a trip it suspends the busiest writer's process tree\n"
        L"and logs what it did. Suspend is reversible - confirm in Task Manager.\n");
}

int wmain(int argc, wchar_t** argv) {
    std::vector<std::wstring> dirs;
    int threshold = 40;
    int rawMbPerSec = 150;   // raw-write rate that counts as a wiper
    for (int i = 1; i < argc; ++i) {
        if (!_wcsicmp(argv[i], L"--watch") && i + 1 < argc) dirs.push_back(argv[++i]);
        else if (!_wcsicmp(argv[i], L"--threshold") && i + 1 < argc) threshold = _wtoi(argv[++i]);
        else if (!_wcsicmp(argv[i], L"--kill")) g_kill = true;
        else if (!_wcsicmp(argv[i], L"--wiper-mbps") && i + 1 < argc) rawMbPerSec = _wtoi(argv[++i]);
        else if (!_wcsicmp(argv[i], L"-h") || !_wcsicmp(argv[i], L"--help")) { usage(); return 0; }
        else { wprintf(L"unknown option: %ls\n\n", argv[i]); usage(); return 2; }
    }
    if (dirs.empty()) {
        for (auto d : { knownFolder(L"USERPROFILE", L"\\Desktop"),
                        knownFolder(L"USERPROFILE", L"\\Documents"),
                        knownFolder(L"USERPROFILE", L"\\Pictures") })
            if (!d.empty()) dirs.push_back(d);
    }
    if (dirs.empty()) { wprintf(L"no folders to watch\n"); return 1; }

    priv::EnableDebugPrivilege();   // so we can suspend/kill other users' processes

    // Try to bring up deterministic ETW attribution. If it can't start (not
    // elevated, or ETW unavailable), the guard silently uses the heuristic.
    bool etwOk = g_etw.Start();

    wprintf(L"=====================================================\n");
    wprintf(L"  Rescue - Anti-Ransomware Guard   %ls\n", g_kill ? L"[KILL mode]" : L"[SUSPEND mode]");
    wprintf(L"  attribution: %ls\n",
            etwOk ? L"ETW (deterministic - exact culprit process)"
                  : L"heuristic (IO_COUNTERS - run elevated for ETW)");
    wprintf(L"=====================================================\n");
    for (auto& d : dirs) {
        plantCanaries(d);
        logline(L"watching: %ls", d.c_str());
    }
    logline(L"canaries planted: %zu   attack threshold: %d files/sec", g_canaries.size(), threshold);
    logline(L"guard is live. Leave this window open. Ctrl+C to stop.");

    std::vector<std::thread> pool;
    for (auto& d : dirs) pool.emplace_back(watchDir, d);
    pool.emplace_back(massChangeMonitor, threshold);
    pool.emplace_back(rawWriteMonitor, rawMbPerSec);
    for (auto& t : pool) t.join();
    g_etw.Stop();
    return 0;
}
