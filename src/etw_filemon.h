// etw_filemon.h - deterministic per-process file-write attribution WITHOUT a
// kernel driver, via Event Tracing for Windows.
//
// The whole reason Module 3 fell back to a heuristic ("suspend the busiest
// writer") is that ReadDirectoryChangesW tells you *that* a file changed, never
// *which process* changed it. Windows does expose that fact to user mode -
// through the manifest ETW provider Microsoft-Windows-Kernel-File, whose
// WRITE / DELETE_PATH / RENAME events each carry the requesting process id in
// the event header (EVENT_HEADER.ProcessId).
//
// So this runs a real-time ETW session, enables ONLY the modify-class keywords,
// and keeps a per-PID counter of file-modifying operations. When the guard
// trips, it reads those counters instead of guessing from IO_COUNTERS - turning
// "probably the culprit" into "this PID performed N file writes in the window".
//
// What this is NOT: it is observe-only. ETW delivers events after the write has
// already been serviced by the filesystem, and it cannot block a write the way
// an in-kernel minifilter's pre-operation callback can. That single capability
// - refusing a write before it lands - is the only thing that still needs the
// signed driver in Phase 6. Attribution does not; this gives it for free, with
// Secure Boot and HVCI left fully on. Requires elevation (a real-time ETW
// session needs it); degrades gracefully to the old heuristic if it can't start.
//
// Deliberately decodes nothing from the event payload: the ProcessId in the
// event header and the enabled keyword are all we need to attribute and count,
// so there is no TDH dependency and nothing to misparse.
#pragma once
#include <windows.h>
#include <evntrace.h>
#include <evntcons.h>
#include <cstdio>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <thread>

namespace etwmon {

// Microsoft-Windows-Kernel-File  {EDD08927-9CC4-4E65-B970-C2560FB5C289}
static const GUID kKernelFileGuid =
    {0xEDD08927,0x9CC4,0x4E65,{0xB9,0x70,0xC2,0x56,0x0F,0xB5,0xC2,0x89}};

// Keyword bits from the provider manifest. Enabling only these means the
// session receives file *modifications* and nothing else - no reads, no opens,
// no metadata noise - so the per-PID counts are writes/renames/deletes only.
static const ULONGLONG KW_WRITE               = 0x0200;
static const ULONGLONG KW_DELETE_PATH         = 0x0400;
static const ULONGLONG KW_RENAME_SETLINK_PATH = 0x0800;

static const wchar_t* kSessionName = L"RescueFileMon";

class FileMonitor {
public:
    // Start the real-time session and its consumer thread. Returns false (and
    // changes nothing) if ETW is unavailable - the caller then keeps using the
    // IO_COUNTERS heuristic.
    bool Start() {
        // A leftover session from a crashed run would make StartTrace fail with
        // ERROR_ALREADY_EXISTS; stop any stale one by name first.
        StopByName();

        size_t nameBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
        propsSize_ = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
        props_ = (EVENT_TRACE_PROPERTIES*)calloc(1, propsSize_);
        if (!props_) return false;
        props_->Wnode.BufferSize = (ULONG)propsSize_;
        props_->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
        props_->Wnode.ClientContext = 1;            // QPC timestamps
        props_->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
        props_->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);

        ULONG rc = StartTraceW(&session_, kSessionName, props_);
        if (rc != ERROR_SUCCESS) { cleanup(); return false; }

        rc = EnableTraceEx2(session_, &kKernelFileGuid,
                            EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                            TRACE_LEVEL_INFORMATION,
                            KW_WRITE | KW_DELETE_PATH | KW_RENAME_SETLINK_PATH,
                            0, 0, nullptr);
        if (rc != ERROR_SUCCESS) { StopByHandle(); cleanup(); return false; }

        EVENT_TRACE_LOGFILEW lf{};
        lf.LoggerName = const_cast<wchar_t*>(kSessionName);
        lf.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD;
        lf.EventRecordCallback = &FileMonitor::RecordThunk;
        lf.Context = this;
        consumer_ = OpenTraceW(&lf);
        if (consumer_ == (TRACEHANDLE)INVALID_HANDLE_VALUE) { StopByHandle(); cleanup(); return false; }

        instance_ = this;
        running_ = true;
        worker_ = std::thread([this]{
            // ProcessTrace blocks here delivering callbacks until the session
            // is stopped, at which point it returns.
            ProcessTrace(&consumer_, 1, nullptr, nullptr);
        });
        return true;
    }

    void Stop() {
        if (!running_) return;
        running_ = false;
        StopByHandle();                 // makes ProcessTrace return
        if (consumer_ != (TRACEHANDLE)INVALID_HANDLE_VALUE) CloseTrace(consumer_);
        if (worker_.joinable()) worker_.join();
        cleanup();
        instance_ = nullptr;
    }

    ~FileMonitor() { Stop(); }

    // Zero every per-PID counter (call at the start of a measurement window).
    void Reset() {
        std::lock_guard<std::mutex> lk(mx_);
        counts_.clear();
    }

    // The PID with the most file-modifying events since the last Reset, and how
    // many - deterministic attribution, not a write-rate guess. Optionally
    // excludes PIDs the caller must not touch (protected system processes).
    DWORD TopWriter(ULONGLONG* countOut,
                    bool (*exclude)(DWORD) = nullptr) {
        std::lock_guard<std::mutex> lk(mx_);
        DWORD top = 0; ULONGLONG best = 0;
        for (auto& kv : counts_) {
            if (kv.first == 0 || kv.first == 4) continue;   // Idle / System
            if (exclude && exclude(kv.first)) continue;
            if (kv.second > best) { best = kv.second; top = kv.first; }
        }
        if (countOut) *countOut = best;
        return top;
    }

    bool Running() const { return running_; }

private:
    static void WINAPI RecordThunk(EVENT_RECORD* rec) {
        auto* self = reinterpret_cast<FileMonitor*>(rec->UserContext);
        if (!self) self = instance_;
        if (self) self->OnRecord(rec);
    }

    void OnRecord(EVENT_RECORD* rec) {
        // Every enabled event is a modify-class op; the header names the process
        // that issued it. Counting by that PID is the whole attribution.
        DWORD pid = rec->EventHeader.ProcessId;
        if (pid == 0 || pid == (DWORD)-1) return;
        std::lock_guard<std::mutex> lk(mx_);
        ++counts_[pid];
    }

    void StopByHandle() {
        if (session_) {
            // ControlTrace needs a properties block; reuse ours.
            if (props_) ControlTraceW(session_, nullptr, props_, EVENT_TRACE_CONTROL_STOP);
            session_ = 0;
        }
    }

    // Stop a session that outlived a previous process, addressed by name.
    static void StopByName() {
        size_t nameBytes = (wcslen(kSessionName) + 1) * sizeof(wchar_t);
        size_t sz = sizeof(EVENT_TRACE_PROPERTIES) + nameBytes;
        auto* p = (EVENT_TRACE_PROPERTIES*)calloc(1, sz);
        if (!p) return;
        p->Wnode.BufferSize = (ULONG)sz;
        p->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        ControlTraceW(0, kSessionName, p, EVENT_TRACE_CONTROL_STOP);
        free(p);
    }

    void cleanup() { if (props_) { free(props_); props_ = nullptr; } }

    TRACEHANDLE session_ = 0;
    TRACEHANDLE consumer_ = (TRACEHANDLE)INVALID_HANDLE_VALUE;
    EVENT_TRACE_PROPERTIES* props_ = nullptr;
    size_t propsSize_ = 0;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::mutex mx_;
    std::unordered_map<DWORD, ULONGLONG> counts_;
    static FileMonitor* instance_;
};

inline FileMonitor* FileMonitor::instance_ = nullptr;

} // namespace etwmon
